use std::collections::BTreeMap;
use std::ffi::c_void;
use std::{ptr, slice, str};

use kraken_mount_pkg::{Error, PRead};
use sha3::{Digest, Sha3_256};

use super::{prepare, prepare_patched, PackageIo, Pkg};

const PAGE: usize = 0x1_0000;
const BLOCK: usize = 4 * PAGE;
const IMAGE: usize = 8 * PAGE;
const OUTER_TABLE: usize = 2 * PAGE;
const LAYOUT: usize = 7 * PAGE;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn dirent(bytes: &mut [u8], offset: usize, inode: u32, kind: u32, name: &str) -> usize {
    let length = (16 + name.len()).next_multiple_of(8);
    put32(bytes, offset, inode);
    put32(bytes, offset + 4, kind);
    put32(bytes, offset + 8, name.len() as u32);
    put32(bytes, offset + 12, length as u32);
    bytes[offset + 16..offset + 16 + name.len()].copy_from_slice(name.as_bytes());
    offset + length
}

fn outer_inode(pkg: &mut [u8], inode: usize, size: usize, first_block: u32) {
    let offset = OUTER_TABLE + inode * 0x2c8;
    put64(pkg, offset + 8, size as u64);
    for block in 0..size.div_ceil(PAGE) {
        put32(pkg, offset + 0x64 + 32 + block * 36, first_block + block as u32);
    }
}

fn inner_inode(image: &mut [u8], inode: usize, mode: u16, offset: usize, len: usize) {
    // The superblock sits after one stored payload page, then the inode table.
    let start = 2 * PAGE + inode * 0xa8;
    image[start..start + 2].copy_from_slice(&mode.to_le_bytes());
    put64(image, start + 8, len as u64);
    put64(image, start + 0x60, offset as u64);
}

const RUN_END: u128 = 1 << 66;

fn kraken_record(logical: usize, stored_end: usize, len: usize) -> u128 {
    let mut record = (logical % BLOCK / 16) as u128;
    record |= ((len.min(BLOCK / 2) - 1) as u128) << 14;
    if len > BLOCK / 2 {
        record |= 4 << 32; // Raw odd half.
    }
    record | ((stored_end % BLOCK) as u128) << 48
}

fn lz_asset() -> Vec<u8> {
    let mut stored = b"rusttest".to_vec();
    stored.push(0x80); // No length escapes.
    for array in [&b"end"[..], &[60], &[], &[23]] {
        stored.extend_from_slice(&[0, 0, array.len() as u8]);
        stored.extend_from_slice(array);
    }
    stored
}

// Synthetic plaintext debug package with an all-zero file followed by a
// stored file and the inode table. The all-zero file has no stored records.
fn synthetic_pkg(zero_len: usize) -> Vec<u8> {
    synthetic_pkg_with_assets(zero_len, &[], None)
}

fn synthetic_pkg_with_assets(zero_len: usize, leading_raw: &[u8], compressed: Option<(&[u8], usize, u8)>) -> Vec<u8> {
    let data_base = zero_len.next_multiple_of(PAGE);
    let padding = data_base - zero_len;
    let first_asset = leading_raw.len() + padding;
    let meta = data_base + PAGE;
    let mount_end = meta + 3 * PAGE;
    let stored_meta = first_asset + PAGE;
    let stored_size = stored_meta + 3 * PAGE;
    let cnt = IMAGE + stored_size.next_multiple_of(PAGE);
    let mut pkg = vec![0; cnt + 0x1000];
    pkg[..4].copy_from_slice(b"\x7fFIH");
    put64(&mut pkg, 0x10, PAGE as u64);
    put64(&mut pkg, 0x18, (cnt - PAGE) as u64);
    put64(&mut pkg, 0x20, PAGE as u64);
    put32(&mut pkg, 0x50, (meta / PAGE) as u32);
    put64(&mut pkg, 0x58, cnt as u64);
    put64(&mut pkg, 0x60, PAGE as u64);
    pkg[cnt..cnt + 4].copy_from_slice(b"\x7fCNT");
    put64(&mut pkg, PAGE, 2);
    put64(&mut pkg, PAGE + 8, 20_130_315);
    put64(&mut pkg, PAGE + 0x30, 4);
    put32(&mut pkg, PAGE + 0xd8, 1);
    pkg[PAGE + 0x370..PAGE + 0x380].copy_from_slice(b"PPRPLAIN-NOAUTH!");
    let root_end = dirent(&mut pkg, 3 * PAGE, 1, 3, "uroot");
    outer_inode(&mut pkg, 0, root_end - 3 * PAGE, 2);
    let image_end = dirent(&mut pkg, 4 * PAGE, 2, 2, "pfs_image.dat");
    let desc_end = dirent(&mut pkg, image_end, 3, 2, "naps_pkg_layout.dat");
    outer_inode(&mut pkg, 1, desc_end - 4 * PAGE, 3);
    outer_inode(&mut pkg, 2, stored_size, 7);

    let mut bounds = vec![(0, 0x40)];
    let mut records = vec![0u128]; // The first stored block starts at offset zero.
    if !leading_raw.is_empty() {
        let logical = zero_len - leading_raw.len();
        bounds.push((logical, 0));
        records[0] = ((logical % BLOCK / 16) as u128) << 68;
        records.push(kraken_record(logical, leading_raw.len(), leading_raw.len()));
    }
    if padding != 0 {
        bounds.push((zero_len, 0));
        records.push(kraken_record(zero_len, first_asset, padding));
    }
    bounds.extend((0..4).map(|slot| (data_base + slot * 128, 0)));
    bounds.extend([(meta, 0), (mount_end, 0x40)]);
    for slot in 0..4 {
        let end = if slot == 3 { PAGE } else { (slot + 1) * 128 };
        let mut record = kraken_record(data_base + slot * 128, first_asset + end, end - slot * 128);
        if let Some((stored, _, _)) = compressed.filter(|_| slot == 0) {
            record = kraken_record(data_base, first_asset + stored.len(), stored.len()) | 2 << 32 | RUN_END;
        }
        records.push(record);
        if compressed.is_some() && slot == 0 {
            // The next file is aligned at 128 bytes. The gap has no stored LZ bytes.
            let at = first_asset + 128;
            records.push(((at as u128 / BLOCK as u128) << 26) | ((at % BLOCK) as u128) << 48);
        }
    }
    records.push(kraken_record(meta, stored_size, 3 * PAGE) | RUN_END);
    records.extend([1 << 67, 0]); // Terminator and sentinel.
    let ublocks = mount_end.div_ceil(BLOCK);
    let first_record = (16 + bounds.len() * 6 + (ublocks / 8 + 1) * 10).next_multiple_of(8) + 3;
    let descriptor_len = first_record + 9 * records.len();
    let layout = &mut pkg[LAYOUT..LAYOUT + descriptor_len];
    put64(layout, 0, ((bounds.len() - 1) as u64) | 2 << 24 | (ublocks as u64) << 32);
    put64(layout, 8, ((records.len() - 2) as u64) << 24);
    if let Some((_, _, tag)) = compressed {
        layout[first_record - 1] = tag;
    }
    for (entry, (offset, kind)) in layout[16..].chunks_exact_mut(6).zip(bounds) {
        entry[..5].copy_from_slice(&(offset as u64).to_le_bytes()[..5]);
        entry[5] = kind;
    }
    for (entry, record) in layout[first_record..].chunks_exact_mut(9).zip(records) {
        entry.copy_from_slice(&record.to_le_bytes()[..9]);
    }
    outer_inode(&mut pkg, 3, descriptor_len, 6);

    let image = &mut pkg[IMAGE..IMAGE + stored_size];
    image[..leading_raw.len()].copy_from_slice(leading_raw);
    // Build the inner metadata using its layout relative to the stored payload.
    let image = &mut image[first_asset..];
    let data_files = [
        (6, "other.bin", &b"asset from package"[..]),
        (7, "eboot.bin", &b"synthetic executable"[..]),
        (8, "param.json", &b"{}"[..]),
        (9, "icon0.png", &b"icon"[..]),
    ];
    for (i, (inode, _, bytes)) in data_files.iter().enumerate() {
        let slot = i * 128;
        image[slot..slot + bytes.len()].copy_from_slice(bytes);
        inner_inode(image, *inode, 0x8000, data_base + slot, bytes.len());
    }
    if let Some((stored, size, _)) = compressed {
        image[..128].fill(0);
        image[..stored.len()].copy_from_slice(stored);
        inner_inode(image, 6, 0x8000, data_base, size);
    }
    put64(image, PAGE, 2);
    put64(image, PAGE + 8, 20_130_315);
    put32(image, PAGE + 0x20, PAGE as u32);
    put64(image, PAGE + 0x30, 10);
    inner_inode(image, 5, 0x8000, 0, zero_len);
    let start = 3 * PAGE;
    let mut end = dirent(image, start, 5, 2, "zero.bin");
    end = dirent(image, end, 6, 2, "other.bin");
    end = dirent(image, end, 7, 2, "eboot.bin");
    end = dirent(image, end, 3, 3, "sce_sys");
    inner_inode(image, 4, 0x4000, meta + 2 * PAGE, end - start);
    let start = end;
    end = dirent(image, end, 8, 2, "param.json");
    end = dirent(image, end, 9, 2, "icon0.png");
    inner_inode(image, 3, 0x4000, meta + start - PAGE, end - start);
    pkg
}

struct TestIo {
    pkg: Vec<u8>,
    files: BTreeMap<String, Vec<u8>>,
}

unsafe extern "C" fn read(context: *mut c_void, offset: u64, out: *mut u8, size: usize) -> isize {
    let io = unsafe { &*context.cast::<TestIo>() };
    let Some(bytes) = io.pkg.get(offset as usize..) else { return 0 };
    let size = size.min(bytes.len());
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, size) };
    size as isize
}

unsafe extern "C" fn write(context: *mut c_void, name: *const u8, name_len: usize,
                            offset: u64, data: *const u8, size: usize) -> i32 {
    let io = unsafe { &mut *context.cast::<TestIo>() };
    let name = str::from_utf8(unsafe { slice::from_raw_parts(name, name_len) }).unwrap();
    let file = io.files.entry(name.into()).or_default();
    let end = offset as usize + size;
        if end > file.len() {
            file.resize(end, 0);
        }
    file[offset as usize..end].copy_from_slice(unsafe { slice::from_raw_parts(data, size) });
    0
}

unsafe extern "C" fn loose_size(_: *mut c_void, _: *const u8, _: usize, _: *mut u64) -> i32 {
    0
}

#[test]
fn sparse_pkg_uses_a_shared_zero_volume() {
    for zero_len in [BLOCK * 2, BLOCK + PAGE / 2] {
        let mut io = TestIo { pkg: synthetic_pkg(zero_len), files: BTreeMap::new() };
        let reader = PackageIo { context: ptr::from_mut(&mut io).cast(), read, write, loose_size };
        let pkg = Pkg::open(&reader, io.pkg.len() as u64).unwrap();
        let entry = pkg.lookup("zero.bin").unwrap();
        assert!(pkg.extents(&entry).is_err());
        assert!(pkg.blocks(&entry).unwrap().iter().all(|block| block.stored_len == 0));
        let mut across_blocks = [0xff; 128];
        assert_eq!(pkg.read_at(&reader, &entry, BLOCK as u64 - 64, &mut across_blocks).unwrap(), 128);
        assert_eq!(across_blocks, [0; 128]);

        prepare(&reader, io.pkg.len() as u64, 0, "sample.pkg").unwrap();
        assert_eq!(io.files["eboot.bin"], b"synthetic executable");
        assert_eq!(io.files["kraken.image"], b"kraken/sample.pkg");
        assert!(!io.files.contains_key("zero.bin"));
        assert!(!io.files.contains_key("other.bin"));
        let manifest = &io.files["ampr_assets.index"];
        let volume = &io.files[".smp-kraken-zero.pak"];
        assert_eq!(volume.len(), PAGE + BLOCK);
        assert_eq!(&volume[..8], b"AMPRDAT3");
        assert_eq!(&volume[24..40], &manifest[24..40]);
        assert_eq!(get32(manifest, 56), 2);
        let start = get64(manifest, 80) as usize;
        let end = get64(manifest, 88) as usize;
        let mut chunks = manifest[start..end].chunks_exact(12);
        let original = chunks.next().unwrap();
        assert_eq!(get64(original, 0) >> 48, 0);
        let offset = get64(original, 0) as usize;
        assert_eq!(&io.pkg[offset..offset + 18], b"asset from package");
        let zero_chunks: Vec<_> = chunks.collect();
        assert_eq!(zero_chunks.len(), 2);
        for (i, chunk) in zero_chunks.iter().enumerate() {
            assert_eq!(get64(chunk, 0) >> 48, 1);
            let offset = (get64(chunk, 0) & ((1 << 48) - 1)) as usize;
            let size = ((get32(chunk, 8) & 0x000f_ffff) + 1) as usize;
            assert_eq!(offset, PAGE);
            assert_eq!(size, (zero_len - i * BLOCK).min(BLOCK));
            assert!(volume[offset..offset + size].iter().all(|&byte| byte == 0));
        }
    }
}

struct TestRead(Vec<u8>);

impl PRead for TestRead {
    fn pread(&self, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let Some(bytes) = self.0.get(off as usize..) else { return Ok(0) };
        let len = bytes.len().min(buf.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(len)
    }
}

fn with_digests(mut pkg: Vec<u8>, content_id: &[u8; 36]) -> Vec<u8> {
    let cnt = get64(&pkg, 0x58) as usize;
    let bytes = (cnt - PAGE) / PAGE * 32;
    let table = 0x200;
    let imagedigs = 0x300;
    pkg.resize(cnt + (imagedigs + bytes).max(0x1000), 0);
    pkg[6] = 3;
    pkg[cnt + 0x40..cnt + 0x64].copy_from_slice(content_id);
    for (offset, value) in [(0x10, 1), (0x18, table), (table, 0x040a),
                            (table + 16, imagedigs), (table + 20, bytes)] {
        pkg[cnt + offset..cnt + offset + 4].copy_from_slice(&(value as u32).to_be_bytes());
    }
    for i in 0..bytes / 32 {
        let at = PAGE + i * PAGE;
        let mut hash: [u8; 32] = Sha3_256::digest(&pkg[at..at + PAGE]).into();
        hash.reverse();
        let offset = cnt + imagedigs + i * 32;
        pkg[offset..offset + 32].copy_from_slice(&hash);
    }
    pkg
}

fn make_patch(base: &[u8], target: &[u8]) -> TestRead {
    let cnt = get64(target, 0x58) as usize;
    let mut patch = vec![0; PAGE];
    patch[..4].copy_from_slice(b"\x7fLIH");
    patch[6] = 1;
    put64(&mut patch, 0x20, PAGE as u64);
    put64(&mut patch, 0x28, PAGE as u64);
    patch.extend_from_slice(&target[..PAGE]);
    for (i, bytes) in target[PAGE..cnt].chunks_exact(PAGE).enumerate() {
        let at = PAGE + i * PAGE;
        if base.get(at..at + PAGE) != Some(bytes) {
            patch.extend_from_slice(bytes);
        }
    }
    let stored_end = patch.len() as u64;
    patch.extend_from_slice(&target[cnt..]);
    let total = patch.len() as u64;
    put64(&mut patch, 0x18, total);
    put64(&mut patch, 0x30, stored_end);
    put64(&mut patch, 0x38, (target.len() - cnt) as u64);
    TestRead(patch)
}

#[test]
fn lih_reads_updated_asset_and_preserves_sparse_chunks() {
    check_lih(b"EP0000-PPSA01234_00-SYNTHETICPACKAGE", b"russian audio data");
}

#[test]
fn lih_decodes_an_lz_file_up_to_its_inode_end() {
    let title = b"UP0001-PPSA54321_00-SYNTHETICPACKAGE";
    let base = with_digests(synthetic_pkg(BLOCK), title);
    let stored = lz_asset();
    let expected = b"rusttest".repeat(6).into_iter().chain(*b"end").collect::<Vec<_>>();
    for (size, tag, encoded) in [
        (expected.len(), 6, stored.clone()),
        (expected.len() + 1, 6, stored.clone()),
        (expected.len(), 4, stored.clone()),
        (expected.len(), 6, { let mut bytes = stored.clone(); bytes.push(0); bytes }),
    ] {
        let target = with_digests(synthetic_pkg_with_assets(BLOCK, &[], Some((&encoded, size, tag))), title);
        let patch = make_patch(&base, &target);
        let mut io = TestIo { pkg: base.clone(), files: BTreeMap::new() };
        let reader = PackageIo { context: ptr::from_mut(&mut io).cast(), read, write, loose_size };
        let result = prepare_patched(&reader, &patch, base.len() as u64, patch.0.len() as u64,
                                     1, "base.pkg", |_, _, _| {}, || false);
        if size == expected.len() && tag == 6 && encoded == stored {
            result.unwrap();
            let manifest = &io.files["ampr_assets.index"];
            let loc = get64(manifest, get64(manifest, 80) as usize);
            assert_eq!(loc >> 48, 1);
            let offset = (loc & ((1 << 48) - 1)) as usize;
            assert_eq!(&io.files[".smp-kraken-patch.pak"][offset..offset + size], expected);
        } else {
            let error = result.unwrap_err();
            assert!(matches!(&error, super::BuildError::Decode(message) if message.starts_with("other.bin: Kraken decode failed")), "{error:?}");
            assert!(!io.files.contains_key("ampr_assets.index"));
        }
    }
}

#[test]
fn lih_indexes_chunks_by_file_offset() {
    let title = b"EP0000-PPSA01234_00-SYNTHETICPACKAGE";
    // A 64 KiB hole followed by a full raw block. The second index chunk
    // starts 192 KiB into the raw block.
    let mut raw = vec![0x37; BLOCK];
    raw[BLOCK - PAGE..].fill(0x6b);
    let base = with_digests(synthetic_pkg_with_assets(BLOCK + PAGE, &raw, None), title);
    let mut target = base.clone();
    target[IMAGE + BLOCK..IMAGE + BLOCK + 18].copy_from_slice(b"russian audio data");
    let target = with_digests(target, title);
    let patch = make_patch(&base, &target);
    let mut io = TestIo { pkg: base.clone(), files: BTreeMap::new() };
    let reader = PackageIo { context: ptr::from_mut(&mut io).cast(), read, write, loose_size };
    prepare_patched(&reader, &patch, base.len() as u64, patch.0.len() as u64,
                    1, "base.pkg", |_, _, _| {}, || false).unwrap();
    let manifest = &io.files["ampr_assets.index"];
    let chunks = get64(manifest, 80) as usize;
    let last_chunk = get64(manifest, chunks + 24);
    assert_eq!(last_chunk >> 48, 1);
    let offset = (last_chunk & ((1 << 48) - 1)) as usize;
    assert_eq!(&io.files[".smp-kraken-patch.pak"][offset..offset + PAGE], &raw[BLOCK - PAGE..]);
}

#[test]
fn lih_applies_across_title_ids_and_rejects_another_title() {
    let title = b"UP0001-PPSA54321_00-SYNTHETICPACKAGE";
    let base = with_digests(synthetic_pkg(BLOCK), title);
    let mut different = base.clone();
    different[IMAGE..IMAGE + 18].copy_from_slice(b"updated game asset");
    let target = with_digests(different, b"UP0001-PPSA54322_00-SYNTHETICPACKAGE");
    let patch = make_patch(&base, &target);
    let base = TestRead(base);
    let result = super::lih::View::open(&base, base.0.len() as u64, &patch,
                                       patch.0.len() as u64, || false, |_, _| {});
    assert!(matches!(result, Err(Error::Unsupported(message)) if message.contains("content ID")));
    check_lih(title, b"updated game asset");
}

fn check_lih(content_id: &[u8; 36], asset: &[u8; 18]) {
    let base = with_digests(synthetic_pkg(BLOCK), content_id);
    let mut updated = base.clone();
    updated[IMAGE..IMAGE + asset.len()].copy_from_slice(asset);
    let target = with_digests(updated, content_id);
    let patch = make_patch(&base, &target);
    let base_size = base.len() as u64;
    let patch_size = patch.0.len() as u64;
    let mut io = TestIo { pkg: base, files: BTreeMap::new() };
    let reader = PackageIo { context: ptr::from_mut(&mut io).cast(), read, write, loose_size };
    let view = super::lih::View::open(&reader, base_size, &patch, patch_size, || false, |_, _| {}).unwrap();
    let mut result = vec![0; target.len()];
    assert_eq!(view.pread(0, &mut result).unwrap(), target.len());
    assert_eq!(result, target);
    let phases = std::cell::Cell::new(0);
    prepare_patched(&reader, &patch, base_size, patch_size, 1, "base.pkg", |phase, _, _| {
        phases.set(phases.get() | 1 << phase);
    }, || false).unwrap();
    assert_eq!(phases.get(), 0b111);
    assert_eq!(io.files["eboot.bin"], b"synthetic executable");
    assert_eq!(io.files["kraken.image"], b"kraken/base.pkg");
    assert!(!io.files.contains_key("other.bin"));
    let manifest = &io.files["ampr_assets.index"];
    assert_eq!(get32(manifest, 56), 2);
    let chunks = get64(manifest, 80) as usize;
    let loc = get64(manifest, chunks);
    let zero_loc = get64(manifest, chunks + 12);
    assert_eq!(loc >> 48, 1);
    assert_eq!(zero_loc >> 48, 1);
    let volume = &io.files[".smp-kraken-patch.pak"];
    assert_eq!(&volume[..8], b"AMPRDAT3");
    assert_eq!(&volume[24..40], &manifest[24..40]);
    assert_eq!(volume.len(), 2 * PAGE + BLOCK);
    let offset = (loc & ((1 << 48) - 1)) as usize;
    assert_eq!(&volume[offset..offset + asset.len()], asset);
    let zero_offset = (zero_loc & ((1 << 48) - 1)) as usize;
    assert!(volume[zero_offset..zero_offset + BLOCK].iter().all(|byte| *byte == 0));

    io.pkg[3 * PAGE + 500] ^= 1;
    io.files.clear();
    let err = prepare_patched(&reader, &patch, base_size, patch_size, 1, "base.pkg", |_, _, _| {}, || false)
        .unwrap_err();
    assert!(matches!(&err, super::BuildError::Other(msg) if msg.contains("fails its LIH digest")), "{err:?}");
    assert!(io.files.is_empty());
    io.pkg = with_digests(io.pkg, content_id);
    let err = prepare_patched(&reader, &patch, base_size, patch_size, 1, "base.pkg", |_, _, _| {}, || false)
        .unwrap_err();
    assert!(matches!(&err, super::BuildError::Other(msg) if msg.contains("blocks absent")), "{err:?}");
    assert!(io.files.is_empty());
}
