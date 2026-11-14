//! Adapts Kraken Mount's plaintext package reader and index writer to SMP.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[path = "../../vendor/kraken/src/ampr_index.rs"]
mod ampr_index;

use alloc::{collections::BTreeMap, format, string::String, vec, vec::Vec};
use ampr_index::{Chunk, IndexFile, Kraken};
use core::{ffi::c_void, ptr, slice, str};
#[cfg(not(test))]
use core::{alloc::{GlobalAlloc, Layout}, panic::PanicInfo};
use kraken_mount_pkg::{Entry, PRead, Pkg};

const COPY_BUFFER: usize = 1024 * 1024;
const REQUIRED_FILES: [&str; 3] = ["eboot.bin", "sce_sys/param.json", "sce_sys/icon0.png"];

#[cfg(not(test))]
extern "C" {
    fn posix_memalign(out: *mut *mut u8, alignment: usize, size: usize) -> i32;
    fn free(ptr: *mut u8);
    fn abort() -> !;
}

#[cfg(not(test))]
struct Allocator;

#[cfg(not(test))]
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut result = ptr::null_mut();
        let alignment = layout.align().max(core::mem::size_of::<usize>());
        if posix_memalign(&mut result, alignment, layout.size()) != 0 {
            return ptr::null_mut();
        }
        result
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr);
    }
}

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    unsafe { abort() }
}

// The prebuilt core references this symbol in its unwind metadata.
// The bridge uses panic=abort and never unwinds across the C boundary.
#[cfg(not(test))]
#[no_mangle]
extern "C" fn rust_eh_personality() -> ! {
    unsafe { abort() }
}

#[cfg(test)]
#[path = "sparse_tests.rs"]
mod sparse_tests;

type Read = unsafe extern "C" fn(*mut c_void, u64, *mut u8, usize) -> isize;
type Write = unsafe extern "C" fn(*mut c_void, *const u8, usize, u64, *const u8, usize) -> i32;
type LooseSize = unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u64) -> i32;

struct PackageIo {
    context: *mut c_void,
    read: Read,
    write: Write,
    loose_size: LooseSize,
}

impl PRead for PackageIo {
    fn pread(&self, offset: u64, buf: &mut [u8]) -> Result<usize, kraken_mount_pkg::Error> {
        let count = unsafe { (self.read)(self.context, offset, buf.as_mut_ptr(), buf.len()) };
        if count < 0 || count as usize > buf.len() {
            return Err(kraken_mount_pkg::Error::Io(count.saturating_neg() as i32));
        }
        Ok(count as usize)
    }
}

impl PackageIo {
    fn output(&self, path: &str, offset: u64, data: &[u8]) -> Result<(), String> {
        let status = unsafe {
            (self.write)(self.context, path.as_ptr(), path.len(), offset, data.as_ptr(), data.len())
        };
        if status == 0 { Ok(()) } else { Err(format!("write {path}: errno {status}")) }
    }

    fn override_size(&self, path: &str) -> Result<Option<u64>, String> {
        let mut size = 0;
        let status = unsafe { (self.loose_size)(self.context, path.as_ptr(), path.len(), &mut size) };
        match status {
            0 => Ok(None),
            1 => Ok(Some(size)),
            code => Err(format!("read staged {path}: errno {}", -code)),
        }
    }

    fn extract(&self, pkg: &Pkg, entry: &Entry<'_>, path: &str, buf: &mut [u8]) -> Result<(), String> {
        if entry.size == 0 {
            return self.output(path, 0, &[]);
        }
        let mut offset = 0;
        while offset < entry.size {
            let length = pkg.read_at(self, entry, offset, buf).map_err(|e| format!("{path}: {e}"))?;
            if length == 0 || length as u64 > entry.size - offset {
                return Err(format!("{path}: short package read"));
            }
            self.output(path, offset, &buf[..length])?;
            offset += length as u64;
        }
        Ok(())
    }
}

fn prepare(io: &PackageIo, size: u64, mtime: i64, basename: &str) -> Result<(), String> {
    let pkg = Pkg::open(io, size).map_err(|e| format!("{e}"))?;
    for path in REQUIRED_FILES {
        if !pkg.lookup(path).is_some_and(|entry| !entry.is_dir && entry.size > 0) {
            return Err(format!("base game file {path} is missing"));
        }
    }
    let mut buffer = vec![0; COPY_BUFFER];
    let mut files = BTreeMap::new();
    let primary_lib = if pkg.files().any(|f| !f.is_dir && f.path.to_ascii_lowercase().starts_with("fakelib2/")) {
        "fakelib2/"
    } else {
        "fakelib/"
    };
    for entry in pkg.files().filter(|f| !f.is_dir) {
        ampr_index::check_path(entry.path)?;
        let lower = entry.path.to_ascii_lowercase();
        if let Some(name) = lower.strip_prefix(primary_lib) {
            if !name.contains('/') && !matches!(name, "libkernel.sprx" | "libsceampr.sprx") {
                let name = &entry.path[primary_lib.len()..];
                let out = format!("fakelib2/{name}");
                if io.override_size(&out)?.is_none() {
                    io.extract(&pkg, &entry, &out, &mut buffer)?;
                }
            }
            continue;
        }
        if lower.starts_with("fakelib/") || lower.starts_with("fakelib2/") || lower == "ampr_emu.index" {
            continue;
        }
        if matches!(lower.as_str(), "ampr_assets.index" | "ampr_zstd.index") {
            return Err(format!("package contains {lower}; nested AMPR packs are unsupported"));
        }
        if lower == "kraken" || lower.starts_with("kraken/") || lower == "kraken.image" || lower.starts_with(".smp-kraken-") {
            return Err(format!("reserved cache path {}", entry.path));
        }
        if files.contains_key(&lower) {
            return Err(format!("case-insensitive duplicate {}", entry.path));
        }
        let loose = io.override_size(entry.path)?;
        let extract = lower.starts_with("sce_sys/") || matches!(lower.as_str(), "eboot.bin" | "eboot2.bin") ||
            lower.ends_with(".prx") || lower.ends_with(".sprx");
        let (length, chunks) = if let Some(length) = loose {
            (length, None)
        } else if extract {
            io.extract(&pkg, &entry, entry.path, &mut buffer)?;
            (entry.size, None)
        } else {
            let blocks = pkg.blocks(&entry).map_err(|e| format!("{e}"))?;
            let chunks = blocks.iter().map(|block| Chunk {
                pkg_off: block.pkg_off,
                stored_len: block.stored_len,
                raw_len: block.raw_len,
                kraken: block.compressed.then_some(Kraken { even_len: block.desc.even_len, mode: block.desc.mode }),
            }).collect();
            (entry.size, Some(chunks))
        };
        files.insert(lower, IndexFile { path: String::from(entry.path), size: length, chunks });
    }
    let files: Vec<_> = files.into_values().collect();
    let images = ampr_index::build(size, mtime, &files)?;
    if let Some((name, bytes)) = images.zero_pack {
        io.output(name, 0, &bytes)?;
    }
    io.output("ampr_emu.index", 0, &images.index)?;
    io.output("ampr_assets.index", 0, &images.manifest)?;
    io.output("kraken.image", 0, format!("kraken/{basename}").as_bytes())
}

/// C retains ownership of the context and buffers for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn sm_kraken_build_index(
    context: *mut c_void, size: u64, mtime: i64, basename: *const u8, basename_len: usize,
    read: Read, write: Write, loose_size: LooseSize, error: *mut u8, error_len: usize,
) -> i32 {
    let io = PackageIo { context, read, write, loose_size };
    let result = str::from_utf8(unsafe { slice::from_raw_parts(basename, basename_len) })
        .map_err(|_| String::from("package basename must be UTF-8"))
        .and_then(|name| {
            if name.is_empty() || name.len() > 255 || name.contains(['/', '\\', '\r', '\n', '\0']) {
                return Err(String::from("invalid package basename"));
            }
            prepare(&io, size, mtime, name)
        });
    match result {
        Ok(()) => 0,
        Err(msg) => {
            if error_len > 0 {
                let length = msg.len().min(error_len - 1);
                unsafe {
                    ptr::copy_nonoverlapping(msg.as_ptr(), error, length);
                    *error.add(length) = 0;
                }
            }
            -1
        }
    }
}
