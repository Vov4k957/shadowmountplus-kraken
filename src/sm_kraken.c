#include "sm_platform.h"

#include "sm_kraken.h"

#include "sm_filesystem.h"
#include "sm_gameinfo.h"
#include "sm_log.h"
#include "sm_path_utils.h"
#include "sm_paths.h"
#include "sm_pkg.h"
#include "sm_runtime.h"
#include "sm_scan.h"
#include "sm_shellcore_service.h"
#include "sm_storage.h"
#include <json-c/json.h>

#define KRAKEN_CACHE LOG_DIR "/kraken"
#define KRAKEN_MARKER ".smp-kraken-source"
#define KRAKEN_MANIFEST ".smp-kraken-built"
#define KRAKEN_REVISION "2"
#define KRAKEN_PATCH_REVISION "5"
#define KRAKEN_PATCH_VOLUME ".smp-kraken-patch.pak"

extern const unsigned char sm_kraken_runtime_start[];
extern const unsigned char sm_kraken_runtime_end[];
extern const char sm_kraken_revision[];

typedef ssize_t (*package_read_fn)(void *, uint64_t, unsigned char *, size_t);
typedef int (*package_write_fn)(void *, const unsigned char *, size_t, uint64_t,
                                const unsigned char *, size_t);
typedef int (*package_loose_fn)(void *, const unsigned char *, size_t, uint64_t *);
typedef void (*package_progress_fn)(void *, uint32_t, uint64_t, uint64_t);
typedef int (*package_cancelled_fn)(void *);

extern int sm_kraken_build_index(
    void *ctx, uint64_t size, int64_t mtime, const unsigned char *basename,
    size_t basename_len, package_read_fn read, package_write_fn write,
    package_loose_fn loose, unsigned char *error, size_t error_len);
extern int sm_kraken_build_patched_index(
    void *ctx, uint64_t base_size, uint64_t patch_size, int64_t mtime,
    const unsigned char *basename, size_t basename_len, package_read_fn read,
    package_read_fn read_patch, package_write_fn write, package_loose_fn loose,
    package_progress_fn progress, package_cancelled_fn is_cancelled,
    unsigned char *error, size_t error_len);

typedef struct {
  char path[MAX_PATH];
  char signature[280];
} patch_record_t;

typedef struct {
  int package_fd;
  int patch_fd;
  int patch_output_fd;
  int output_fd;
  int error;
  char output_path[MAX_PATH];
  const char *staging;
  const sm_kraken_job_t *job;
} cache_io_t;

static bool join_path(const char *root, const char *name, char out[MAX_PATH]) {
  int written = snprintf(out, MAX_PATH, "%s/%s", root, name);
  if (written < 0 || written >= MAX_PATH) {
    errno = ENAMETOOLONG;
    return false;
  }
  return true;
}

static bool local_package_root(const char *path) {
  if (path_matches_root_or_child(path, "/data") ||
      path_matches_root_or_child(path, "/user/data"))
    return !path_matches_root_or_child(path, LOG_DIR) &&
           !path_matches_root_or_child(path, "/user" LOG_DIR);
  for (int i = 0; i < 10; i++) {
    char root[16];
    snprintf(root, sizeof(root), i < 8 ? "/mnt/usb%d" : "/mnt/ext%d",
             i < 8 ? i : i - 8);
    if (path_matches_root_or_child(path, root))
      return true;
  }
  return false;
}

bool sm_kraken_is_package(const char *path) {
  if (!path || !local_package_root(path) || !strrchr(path, '/'))
    return false;
  const char *name = strrchr(path, '/') + 1;
  const char *suffix = strrchr(name, '.');
  return suffix && strcasecmp(suffix, ".pkg") == 0 && strlen(name) <= 255u &&
         !strpbrk(path, "\\\r\n") && !strstr(path, "/../") && !strstr(path, "/./");
}

bool sm_kraken_is_cache(const char *path) {
  const size_t prefix = sizeof(KRAKEN_CACHE);
  if (!path || strncmp(path, KRAKEN_CACHE "/", prefix) != 0)
    return false;
  const char *title_id = path + prefix;
  return strlen(title_id) == 9u && strncmp(title_id, "PPSA", 4u) == 0 &&
         is_supported_game_title_id(title_id);
}

static bool package_on_selected_storage(const char *path) {
  char canonical[PATH_MAX];
  if (!realpath(path, canonical))
    return false;
  if (local_package_root(canonical) && !sm_pkg_is_installed_content_path(canonical))
    return true;
  errno = EPERM;
  return false;
}

static int open_source(const sm_pkg_info_t *info, pkg_kind_t kind) {
  if (!info || !sm_kraken_is_package(info->path) ||
      info->pkg_kind != kind || strncmp(info->title_id, "PPSA", 4u) != 0 ||
      !is_supported_game_title_id(info->title_id) ||
      sm_pkg_is_installed_content_path(info->path)) {
    errno = EINVAL;
    return -1;
  }
  if (!package_on_selected_storage(info->path))
    return -1;
  int fd = open(info->path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0)
    return -1;
  struct stat st;
  if (fstat(fd, &st) == 0 && sm_pkg_source_matches(info, &st))
    return fd;
  close(fd);
  errno = EAGAIN;
  return -1;
}

static uint64_t read_le64(const unsigned char bytes[8]) {
  uint64_t result = 0;
  for (size_t i = 0; i < 8u; i++)
    result |= (uint64_t)bytes[i] << (i * 8u);
  return result;
}

bool sm_kraken_can_mount(const sm_pkg_info_t *info) {
  int fd = open_source(info, PKG_KIND_BASE);
  if (fd < 0)
    return false;

  // Check the FIH debug flag and the outer superblock's plaintext marker.
  unsigned char header[0x28] = {0};
  bool supported = pread(fd, header, sizeof(header), 0) == (ssize_t)sizeof(header) &&
                   memcmp(header, "\177FIH", 4) == 0 && header[5] == 0;
  uint64_t offset = read_le64(header + 0x20);
  const char expected[] = "PPRPLAIN-NOAUTH!";
  char marker[sizeof(expected) - 1u];
  const uint64_t marker_end = 0x370u + sizeof(marker);
  supported = supported && offset >= 0x10000u &&
              info->source_size >= marker_end && offset <= info->source_size - marker_end &&
              pread(fd, marker, sizeof(marker), (off_t)(offset + 0x370u)) ==
                  (ssize_t)sizeof(marker) &&
              memcmp(marker, expected, sizeof(marker)) == 0;
  close(fd);
  return supported;
}

bool sm_kraken_can_apply_patch(const sm_pkg_info_t *info) {
  if (!info || !info->is_lih)
    return false;
  int fd = open_source(info, PKG_KIND_PATCH);
  if (fd < 0)
    return false;
  unsigned char header[0x30] = {0};
  bool valid = pread(fd, header, sizeof(header), 0) == (ssize_t)sizeof(header) &&
               memcmp(header, "\177LIH", 4) == 0 && header[6] == 1 && header[7] == 0;
  uint64_t fih = read_le64(header + 0x20);
  unsigned char fih_header[8];
  valid = valid && fih >= 0x10000u && fih <= INT64_MAX &&
          fih <= info->source_size - sizeof(fih_header) &&
          pread(fd, fih_header, sizeof(fih_header), (off_t)fih) == (ssize_t)sizeof(fih_header) &&
          memcmp(fih_header, "\177FIH", 4) == 0 && fih_header[5] == 0 &&
          fih_header[6] == 3 && fih_header[7] == 0;
  close(fd);
  return valid;
}

static bool read_cache_marker(const char *cache, char source[MAX_PATH],
                              char *signature, size_t signature_size,
                              patch_record_t *patch) {
  source[0] = '\0';
  char path[MAX_PATH];
  if (!sm_kraken_is_cache(cache) || !join_path(cache, KRAKEN_MARKER, path))
    return false;
  int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0)
    return false;
  FILE *marker = fdopen(fd, "r");
  if (!marker) {
    close(fd);
    return false;
  }
  bool valid = fgets(source, MAX_PATH, marker) != NULL;
  char *line_end = valid ? strchr(source, '\n') : NULL;
  if (line_end)
    *line_end = '\0';
  valid = line_end && sm_kraken_is_package(source);
  if (valid && signature)
    valid = signature_size > 0 && fgets(signature, (int)signature_size, marker) &&
            strchr(signature, '\n') != NULL;
  if (valid && patch && fgets(patch->path, sizeof(patch->path), marker)) {
    line_end = strchr(patch->path, '\n');
    if (line_end)
      *line_end = '\0';
    valid = line_end && sm_kraken_is_package(patch->path) &&
        fgets(patch->signature, sizeof(patch->signature), marker) != NULL &&
        strchr(patch->signature, '\n') != NULL;
  }
  fclose(marker);
  if (!valid)
    source[0] = '\0';
  return valid;
}

bool sm_kraken_source(const char *cache, char path[MAX_PATH]) {
  return read_cache_marker(cache, path, NULL, 0, NULL);
}

bool sm_kraken_patch_source(const char *cache, char path[MAX_PATH]) {
  char base[MAX_PATH];
  char signature[280];
  patch_record_t patch = {0};
  if (!read_cache_marker(cache, base, signature, sizeof(signature), &patch) ||
      patch.path[0] == '\0')
    return false;
  strlcpy(path, patch.path, MAX_PATH);
  return true;
}

bool sm_kraken_source_ready(const char *cache) {
  char source[MAX_PATH], expected[280], saved[280];
  char index[MAX_PATH];
  if (!read_cache_marker(cache, source, saved, sizeof(saved), NULL) ||
      !join_path(cache, "ampr_assets.index", index) || !path_exists(index)) {
    errno = ENOENT;
    return false;
  }
  struct stat st;
  if (!package_on_selected_storage(source) || lstat(source, &st) != 0)
    return false;
  int written = snprintf(expected, sizeof(expected),
                          "%s %s %llx %llx %llx %llx %lx %llx %lx ",
                          KRAKEN_REVISION, sm_kraken_revision,
                          (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
                          (unsigned long long)st.st_size, (unsigned long long)st.st_mtime,
                          (unsigned long)st.st_mtim.tv_nsec, (unsigned long long)st.st_ctime,
                          (unsigned long)st.st_ctim.tv_nsec);
  if (!S_ISREG(st.st_mode) || written <= 0 || (size_t)written >= sizeof(expected) ||
      strncmp(saved, expected, (size_t)written) != 0) {
    errno = ESTALE;
    return false;
  }
  return true;
}

static bool cancelled(void *unused) {
  (void)unused;
  return should_stop_requested() || runtime_sleep_mode_active();
}

static bool cache_cancelled(const cache_io_t *io) {
  return cancelled(NULL) || io->job->cancelled(io->job->ctx);
}

static int patch_cancelled(void *context) {
  cache_io_t *io = context;
  if (!cache_cancelled(io))
    return 0;
  io->error = ECANCELED;
  return 1;
}

static ssize_t cache_read(cache_io_t *io, int fd, uint64_t offset,
                          unsigned char *buffer, size_t length) {
  if (cache_cancelled(io))
    return -(io->error = ECANCELED);
  if (offset > INT64_MAX)
    return -(io->error = EOVERFLOW);
  ssize_t result;
  do {
    result = pread(fd, buffer, length, (off_t)offset);
  } while (result < 0 && errno == EINTR);
  return result < 0 ? -(io->error = errno) : result;
}

static ssize_t package_read(void *context, uint64_t offset, unsigned char *buffer,
                            size_t length) {
  cache_io_t *io = context;
  return cache_read(io, io->package_fd, offset, buffer, length);
}

static ssize_t patch_read(void *context, uint64_t offset, unsigned char *buffer,
                          size_t length) {
  cache_io_t *io = context;
  return cache_read(io, io->patch_fd, offset, buffer, length);
}

static void patch_progress(void *context, uint32_t phase, uint64_t done, uint64_t total) {
  const cache_io_t *io = context;
  io->job->progress(io->job->ctx, phase, done, total);
}

static bool output_path(cache_io_t *io, const unsigned char *name, size_t length,
                        char path[MAX_PATH]) {
  if (length == 0 || length >= MAX_PATH || memchr(name, '\0', length)) {
    errno = EINVAL;
    return false;
  }
  char relative[MAX_PATH];
  memcpy(relative, name, length);
  relative[length] = '\0';
  return join_path(io->staging, relative, path);
}

static bool make_parents(char *path, size_t root_length) {
  for (char *slash = strchr(path + root_length + 1u, '/'); slash;
       slash = strchr(slash + 1, '/')) {
    *slash = '\0';
    int created = mkdir(path, 0777);
    *slash = '/';
    if (created != 0 && errno != EEXIST)
      return false;
  }
  return true;
}

static int close_output(cache_io_t *io) {
  if (io->output_fd < 0)
    return 0;
  const int status = close(io->output_fd);
  io->output_fd = -1;
  io->output_path[0] = '\0';
  return status;
}

static int stage_write(void *context, const unsigned char *name, size_t length,
                       uint64_t offset, const unsigned char *buffer, size_t count) {
  cache_io_t *io = context;
  char path[MAX_PATH];
  if (cache_cancelled(io))
    return io->error = ECANCELED;
  if (offset > INT64_MAX || count > (uint64_t)INT64_MAX - offset)
    return EOVERFLOW;
  if (!output_path(io, name, length, path))
    return errno;
  const bool patch_volume = length == sizeof(KRAKEN_PATCH_VOLUME) - 1u &&
                           memcmp(name, KRAKEN_PATCH_VOLUME, length) == 0;
  int *fd = patch_volume ? &io->patch_output_fd : &io->output_fd;
  if (*fd < 0 || (!patch_volume && strcmp(io->output_path, path) != 0)) {
    if (!patch_volume && close_output(io) != 0)
      return errno;
    if (!make_parents(path, strlen(io->staging)))
      return errno;
    *fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0777);
    if (*fd < 0)
      return io->error = errno;
    if (!patch_volume)
      strlcpy(io->output_path, path, sizeof(io->output_path));
    if (fchmod(*fd, 0777) != 0)
      return io->error = errno;
  }
  while (count > 0) {
    ssize_t written = pwrite(*fd, buffer, count, (off_t)offset);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return io->error = written == 0 ? EIO : errno;
    offset += (uint64_t)written;
    buffer += written;
    count -= (size_t)written;
  }
  return 0;
}

static int staged_file_size(void *context, const unsigned char *name,
                            size_t length, uint64_t *size) {
  char path[MAX_PATH];
  if (!output_path(context, name, length, path))
    return -errno;
  struct stat st;
  if (lstat(path, &st) != 0)
    return errno == ENOENT ? 0 : -errno;
  if (!S_ISREG(st.st_mode))
    return -EINVAL;
  *size = (uint64_t)st.st_size;
  return 1;
}

static bool reserved_backport_name(const char *name) {
  return strcasecmp(name, "kraken") == 0 || strcasecmp(name, "kraken.image") == 0 ||
         strcasecmp(name, "ampr_emu.index") == 0 || strcasecmp(name, "ampr_assets.index") == 0 ||
         strcasecmp(name, "ampr_zstd.index") == 0 || strncasecmp(name, ".smp-kraken-", 12) == 0;
}

typedef bool (*tree_file_fn)(const char *, const char *, const struct stat *, void *);

// Keep a single path buffer for the walk. lstat prevents descending symlinks.
static bool walk_tree(char path[MAX_PATH], size_t root_length,
                      tree_file_fn visit, void *context) {
  DIR *dir = opendir(path);
  if (!dir)
    return false;
  size_t length = strlen(path);
  int error = 0;
  for (;;) {
    errno = 0;
    const struct dirent *entry = readdir(dir);
    if (!entry) {
      error = errno;
      break;
    }
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    if (cancelled(NULL)) {
      error = ECANCELED;
      break;
    }
    int size = snprintf(path + length, MAX_PATH - length, "/%s", entry->d_name);
    if (size < 0 || (size_t)size >= MAX_PATH - length) {
      error = ENAMETOOLONG;
      break;
    }
    struct stat st;
    if (lstat(path, &st) != 0 || !visit(path, path + root_length + 1u, &st, context) ||
        (S_ISDIR(st.st_mode) && !walk_tree(path, root_length, visit, context))) {
      error = errno ? errno : EIO;
      break;
    }
    path[length] = '\0';
  }
  path[length] = '\0';
  if (closedir(dir) != 0 && error == 0)
    error = errno;
  errno = error;
  return error == 0;
}

static bool record_built_path(const char *path, const char *relative,
                              const struct stat *st, void *context) {
  (void)path;
  (void)st;
  if (json_object_object_add(context, relative, NULL) == 0)
    return true;
  errno = ENOMEM;
  return false;
}

static bool write_build_manifest(const char *staging) {
  char path[MAX_PATH];
  struct json_object *built = json_object_new_object();
  if (!built) {
    errno = ENOMEM;
    return false;
  }
  strlcpy(path, staging, sizeof(path));
  bool ready = walk_tree(path, strlen(staging), record_built_path, built) &&
               join_path(staging, KRAKEN_MANIFEST, path) &&
               json_object_to_file_ext(path, built, JSON_C_TO_STRING_PLAIN) == 0;
  json_object_put(built);
  return ready;
}

typedef struct {
  struct json_object *built;
  const char *staging;
} saved_file_copy_t;

static bool copy_game_written_path(const char *path, const char *relative,
                                   const struct stat *st, void *context) {
  saved_file_copy_t *copy = context;
  if (reserved_backport_name(relative) || json_object_object_get_ex(copy->built, relative, NULL))
    return true;

  char target[MAX_PATH];
  if (!join_path(copy->staging, relative, target))
    return false;
  struct stat new_st;
  if (lstat(target, &new_st) == 0)
    return true; // A current build file owns this path.
  if (errno != ENOENT || !make_parents(target, strlen(copy->staging)))
    return false;
  if (S_ISDIR(st->st_mode))
    return mkdir(target, st->st_mode & 0777) == 0;
  if (S_ISREG(st->st_mode))
    return sm_storage_copy_path_progress(path, target, NULL, cancelled, NULL) == 0;
  if (S_ISLNK(st->st_mode)) {
    char link[MAX_PATH];
    ssize_t count = readlink(path, link, sizeof(link) - 1u);
    if (count < 0)
      return false;
    if ((size_t)count == sizeof(link) - 1u) {
      errno = ENAMETOOLONG;
      return false;
    }
    link[count] = '\0';
    return symlink(link, target) == 0;
  }
  return true;
}

static bool preserve_game_written_files(const char *cache, const char *staging) {
  char path[MAX_PATH];
  if (!join_path(cache, KRAKEN_MANIFEST, path))
    return false;
  int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0)
    return false;
  struct stat st;
  struct json_object *built = fstat(fd, &st) == 0 && S_ISREG(st.st_mode)
                                 ? json_object_from_fd(fd) : NULL;
  close(fd);
  if (!built || !json_object_is_type(built, json_type_object)) {
    if (built) json_object_put(built);
    errno = EINVAL;
    return false;
  }
  saved_file_copy_t copy = {.built = built, .staging = staging};
  strlcpy(path, cache, sizeof(path));
  bool ready = walk_tree(path, strlen(cache), copy_game_written_path, &copy);
  json_object_put(built);
  return ready;
}

static uint64_t hash_bytes(uint64_t value, const void *bytes, size_t length) {
  const unsigned char *data = bytes;
  for (size_t i = 0; i < length; i++) {
    value ^= data[i];
    value *= UINT64_C(1099511628211);
  }
  return value;
}

static bool fingerprint_backport_file(const char *path, const char *relative,
                                      const struct stat *st, void *context) {
  (void)path;
  const uint64_t attributes[] = {st->st_dev, st->st_ino, st->st_mode, st->st_size,
                                 st->st_mtime, st->st_mtim.tv_nsec,
                                 st->st_ctime, st->st_ctim.tv_nsec};
  uint64_t hash = hash_bytes(UINT64_C(14695981039346656037), relative, strlen(relative));
  uint64_t *fingerprint = context;
  *fingerprint += hash_bytes(hash, attributes, sizeof(attributes));
  return true;
}

static bool stage_backport(const char *backport, const char *staging,
                           bool use_patched_metadata) {
  if (!*backport)
    return true;
  DIR *dir = opendir(backport);
  if (!dir)
    return false;
  int error = 0;
  struct dirent *entry;
  while (error == 0) {
    errno = 0;
    entry = readdir(dir);
    if (!entry) {
      error = errno;
      break;
    }
    const char *name = entry->d_name;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        strcasecmp(name, "fakelib") == 0 || strcasecmp(name, "fakelib2") == 0 ||
        reserved_backport_name(name))
      continue;
    if (use_patched_metadata && strcasecmp(name, "sce_sys") == 0)
      continue; // The LIH supplies a coherent version and metadata set.
    char source[MAX_PATH], target[MAX_PATH];
    if (!join_path(backport, name, source) || !join_path(staging, name, target) ||
        sm_storage_copy_path_progress(source, target, NULL, cancelled, NULL) != 0)
      error = errno ? errno : EIO;
  }
  if (closedir(dir) != 0 && error == 0)
    error = errno;
  errno = error;
  return error == 0;
}

static bool stage_backport_libraries(const char *backport, cache_io_t *io) {
  if (!*backport)
    return true;
  char path[MAX_PATH];
  if (!join_path(backport, "fakelib2", path))
    return false;
  DIR *dir = opendir(path);
  if (!dir && errno == ENOENT) {
    if (!join_path(backport, "fakelib", path))
      return false;
    dir = opendir(path);
  }
  if (!dir)
    return errno == ENOENT;

  int error = 0;
  while (error == 0) {
    errno = 0;
    const struct dirent *entry = readdir(dir);
    if (!entry) {
      error = errno;
      break;
    }
    const char *name = entry->d_name;
    if (name[0] == '.' || !strcasecmp(name, "libsceampr.sprx") ||
        !strcasecmp(name, "libkernel.sprx"))
      continue;
    char source[MAX_PATH], target[MAX_PATH], relative[MAX_PATH];
    struct stat st;
    if (!join_path(path, name, source) || lstat(source, &st) != 0) {
      error = errno;
      break;
    }
    if (!S_ISREG(st.st_mode))
      continue;
    if (!join_path("fakelib2", name, relative) ||
        !join_path(io->staging, relative, target) ||
        !make_parents(target, strlen(io->staging)) ||
        sm_storage_copy_path_progress(source, target, NULL, cancelled, NULL) != 0 ||
        chmod(target, 0777) != 0)
      error = errno ? errno : EIO;
  }
  if (closedir(dir) != 0 && error == 0)
    error = errno;
  errno = error;
  return error == 0;
}

static bool source_signature(const sm_pkg_info_t *info, const char *backport,
                             const char *revision, char out[280]) {
  uint64_t signature = 0;
  if (*backport) {
    char path[MAX_PATH];
    strlcpy(path, backport, sizeof(path));
    signature = hash_bytes(UINT64_C(14695981039346656037), path, strlen(path));
    if (!walk_tree(path, strlen(path), fingerprint_backport_file, &signature))
      return false;
  }
  int written = snprintf(out, 280, "%s %s %llx %llx %llx %llx %lx %llx %lx %llx\n",
                         revision, sm_kraken_revision,
                         (unsigned long long)info->source_device, (unsigned long long)info->source_inode,
                         (unsigned long long)info->source_size, (unsigned long long)info->source_mtime,
                         (unsigned long)info->source_mtime_ns, (unsigned long long)info->source_ctime,
                         (unsigned long)info->source_ctime_ns, (unsigned long long)signature);
  if (written <= 0 || written >= 280) {
    errno = EOVERFLOW;
    return false;
  }
  return true;
}

static bool package_unchanged(const sm_pkg_info_t *info, int fd) {
  struct stat original, current;
  return fstat(fd, &original) == 0 && lstat(info->path, &current) == 0 &&
         sm_pkg_source_matches(info, &original) && sm_pkg_source_matches(info, &current);
}

static void remove_staging(const char *path) {
  if (sm_storage_delete_path(path) != 0 && errno != ENOENT)
    log_debug("  [KRAKEN] temporary cache cleanup failed: %s (%s)", path, strerror(errno));
}

static bool publish_cache(const char *title_id, const char *staging,
                          const char *cache, const char *backup) {
  // The full scan already holds the external mutation guard through registration.
  if (cancelled(NULL) || sm_shellcore_title_is_protected(title_id)) {
    errno = EBUSY;
    return false;
  }
  runtime_mount_state_lock();
  bool mounted = is_data_mounted(title_id);
  bool ready = !mounted || unmount_title_runtime_layers_quiet(title_id);
  struct stat old;
  if (ready && lstat(cache, &old) == 0) {
    if (S_ISDIR(old.st_mode))
      ready = preserve_game_written_files(cache, staging) && rename(cache, backup) == 0;
    else {
      errno = EEXIST;
      ready = false;
    }
  } else if (ready && errno != ENOENT) {
    ready = false;
  }
  if (ready && rename(staging, cache) != 0) {
    int saved = errno;
    if (rename(backup, cache) != 0 && errno != ENOENT)
      log_debug("  [KRAKEN] rollback failed; previous cache kept in %s", backup);
    errno = saved;
    ready = false;
  }
  int error = ready ? 0 : errno;
  runtime_mount_state_unlock();
  errno = error;
  return ready;
}

static bool prepare_cache(const sm_pkg_info_t *info, const sm_pkg_info_t *patch,
                          const sm_kraken_job_t *job, char cache[MAX_PATH]) {
  if (!join_path(KRAKEN_CACHE, info->title_id, cache) || !sm_kraken_is_cache(cache))
    return false;
  char existing[MAX_PATH] = "", current[280], saved[280] = "", patch_signature[280] = "";
  patch_record_t old_patch = {0};
  char backport[MAX_PATH] = "", package_dir[MAX_PATH], backup[MAX_PATH];
  strlcpy(package_dir, info->path, sizeof(package_dir));
  char *separator = strrchr(package_dir, '/');
  if (!separator)
    return false;
  *separator = '\0';
  (void)resolve_backport_path_for_title(info->title_id, package_dir, backport);
  if (!source_signature(info, backport, KRAKEN_REVISION, current) ||
      (patch && !source_signature(patch, "", KRAKEN_PATCH_REVISION, patch_signature)))
    return false;

  if (read_cache_marker(cache, existing, saved, sizeof(saved), &old_patch) &&
      strcmp(existing, info->path) == 0) {
    bool intact = sm_kraken_source_ready(cache) && directory_has_game_executable(cache);
    bool same_patch = patch ? strcmp(old_patch.path, patch->path) == 0 &&
                                  strcmp(old_patch.signature, patch_signature) == 0
                            : !old_patch.path[0];
    if (intact && same_patch && strcmp(current, saved) == 0) {
      if (job->finalize(job->ctx))
        return true;
      errno = ECANCELED;
      return false;
    }
  }

  char backup_name[40];
  snprintf(backup_name, sizeof(backup_name), ".previous-%s", info->title_id);
  if (!join_path(KRAKEN_CACHE, backup_name, backup))
    return false;
  if (mkdir(KRAKEN_CACHE, 0777) != 0 && errno != EEXIST)
    return false;
  struct stat st;
  if (lstat(backup, &st) == 0) {
    if (lstat(cache, &st) != 0) {
      if (errno != ENOENT || rename(backup, cache) != 0)
        return false;
    } else if (sm_storage_delete_path(backup) != 0) {
      return false;
    }
  }
  int fd = open_source(info, PKG_KIND_BASE);
  if (fd < 0)
    return false;
  int patch_fd = patch ? open_source(patch, PKG_KIND_PATCH) : -1;
  if (patch && patch_fd < 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return false;
  }
  char staging[] = KRAKEN_CACHE "/.prepare-XXXXXX";
  if (!mkdtemp(staging)) {
    int saved_errno = errno;
    close(fd);
    if (patch_fd >= 0)
      close(patch_fd);
    errno = saved_errno;
    return false;
  }
  cache_io_t io = {.package_fd = fd, .patch_fd = patch_fd, .patch_output_fd = -1,
                   .output_fd = -1, .staging = staging, .job = job};
  char package_mount[MAX_PATH];
  char build_error[MAX_PATH + 256] = "";
  const char *name = strrchr(info->path, '/') + 1;
  bool ready = chmod(staging, 0777) == 0 &&
      join_path(staging, SM_KRAKEN_PACKAGE_DIR, package_mount) &&
      mkdir(package_mount, 0777) == 0 && stage_backport(backport, staging, patch != NULL) &&
      stage_backport_libraries(backport, &io);
  if (ready) {
    const unsigned char *basename = (const unsigned char *)name;
    unsigned char *message = (unsigned char *)build_error;
    int result = patch ? sm_kraken_build_patched_index(
        &io, info->source_size, patch->source_size, (int64_t)patch->source_mtime,
        basename, strlen(name), package_read, patch_read, stage_write,
        staged_file_size, patch_progress, patch_cancelled, message, sizeof(build_error))
        : sm_kraken_build_index(&io, info->source_size, (int64_t)info->source_mtime,
        basename, strlen(name), package_read, stage_write, staged_file_size,
        message, sizeof(build_error));
    ready = result == 0;
    if (!ready)
      errno = io.error ? io.error : (result == -2 ? EILSEQ : EINVAL);
  }
  if (ready) {
    const char runtime[] = "fakelib2/libSceAmpr.sprx";
    int status = stage_write(&io, (const unsigned char *)runtime, sizeof(runtime) - 1u,
        0, sm_kraken_runtime_start, (size_t)(sm_kraken_runtime_end - sm_kraken_runtime_start));
    ready = status == 0;
    if (!ready) errno = status;
  }
  int error = ready ? 0 : (errno ? errno : EIO);
  if (close_output(&io) != 0 && error == 0)
    error = errno;
  if (io.patch_output_fd >= 0 && close(io.patch_output_fd) != 0 && error == 0)
    error = errno;
  char final_signature[280];
  if (error == 0 && (!package_unchanged(info, fd) ||
      !source_signature(info, backport, KRAKEN_REVISION, final_signature) ||
      strcmp(current, final_signature) != 0))
    error = EAGAIN;
  close(fd);
  if (patch_fd >= 0) {
    if (error == 0 && !package_unchanged(patch, patch_fd))
      error = EAGAIN;
    close(patch_fd);
  }
  if (error == 0) {
    sm_pkg_info_t extracted = {0};
    if (!sm_pkg_read_directory_metadata(staging, &extracted) ||
        strcmp(extracted.title_id, info->title_id) != 0 ||
        (patch && (strcmp(extracted.content_id, patch->content_id) != 0 ||
                   (patch->app_ver[0] && strcmp(extracted.app_ver, patch->app_ver) != 0))))
      error = EINVAL;
  }
  if (error == 0 && !write_build_manifest(staging))
    error = errno ? errno : EIO;
  if (error == 0) {
    char marker_path[MAX_PATH];
    FILE *marker = join_path(staging, KRAKEN_MARKER, marker_path)
                       ? fopen(marker_path, "wx") : NULL;
    if (!marker) {
      error = errno ? errno : EIO;
    } else {
      if (fprintf(marker, "%s\n%s", info->path, current) < 0 ||
          (patch && fprintf(marker, "%s\n%s", patch->path, patch_signature) < 0))
        error = errno ? errno : EIO;
      if (fclose(marker) != 0 && error == 0)
        error = errno;
    }
  }
  if (error == 0 && !job->finalize(job->ctx))
    error = ECANCELED;
  if (error == 0 && !publish_cache(info->title_id, staging, cache, backup))
    error = errno ? errno : EIO;
  if (error == 0) {
    remove_staging(backup);
    log_debug("  [KRAKEN] cache ready: %s -> %s", info->path, cache);
    if (patch)
      log_debug("  [KRAKEN] LIH applied: %s %s: %s", patch->title_id,
                patch->app_ver, patch->path);
  } else {
    remove_staging(staging);
    log_debug("  [KRAKEN] cache failed: %s: %s", info->path,
              *build_error ? build_error : strerror(error));
  }
  errno = error;
  return error == 0;
}

bool sm_kraken_prepare_base(const sm_pkg_info_t *info, const sm_kraken_job_t *job,
                            char cache[MAX_PATH]) {
  return prepare_cache(info, NULL, job, cache);
}

bool sm_kraken_apply_patch(const sm_pkg_info_t *base, const sm_pkg_info_t *patch,
                           const sm_kraken_job_t *job) {
  if (strcmp(base->title_id, patch->title_id) != 0 || !base->content_id[0] ||
      strcmp(base->content_id, patch->content_id) != 0) {
    log_debug("  [KRAKEN] LIH identity mismatch: base=%s (%s), patch=%s (%s)",
              base->title_id, base->content_id, patch->title_id, patch->content_id);
    errno = EINVAL;
    return false;
  }
  char cache[MAX_PATH];
  return prepare_cache(base, patch, job, cache);
}
