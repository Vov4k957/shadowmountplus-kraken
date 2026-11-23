/*
 * PS5Save M.2 slot reader/copy engine, adapted from the user's
 * PS5Upload-12.4.20-PS5Save-M2 fork (GPL-3.0-or-later).
 * Unlike an ordinary file copy, this edits a TEMPORARILY MOUNTED save image
 * and keeps the destination's own sce_sys metadata.
 */
#include "sm_ps5save_restore.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__FreeBSD__) || defined(__APPLE__)
#define SM_STAT_MTIME(st) ((st).st_mtimespec)
#define SM_STAT_CTIME(st) ((st).st_ctimespec)
#else
#define SM_STAT_MTIME(st) ((st).st_mtim)
#define SM_STAT_CTIME(st) ((st).st_ctim)
#endif

#define SM_SAVE_TREE_DEPTH_MAX 32
#define SM_SAVE_COPY_CHUNK (256u * 1024u)

static int suffix(const char *name, const char *ending) {
  size_t n = strlen(name), e = strlen(ending);
  return n >= e && strcmp(name + n - e, ending) == 0;
}
static int hex_user(const char *s, size_t minimum) {
  size_t n = strlen(s);
  return n >= minimum && n <= 8 &&
      strspn(s, "0123456789abcdefABCDEF") == n;
}
static int title_id(const char *s) {
  return strlen(s) == 9 &&
      strspn(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 4 &&
      strspn(s + 4, "0123456789") == 5;
}
int sm_ps5save_legacy_date(const char *s) {
  return strlen(s) == 10 && strspn(s, "0123456789") == 4 &&
       s[4] == '-' && strspn(s + 5, "0123456789") == 2 &&
       s[7] == '-' && strspn(s + 8, "0123456789") == 2;
}
int sm_ps5save_version_name(const char *s) {
  return strlen(s) == SM_PS5SAVE_VERSION_SIZE - 1 && s[0] == 'v' &&
      strspn(s + 1, "0123456789") == SM_PS5SAVE_VERSION_SIZE - 2;
}
static int filename(const char *s) {
  if (!*s || *s == '.') return 0;
  for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    if (*p < 32 || *p == 127 || *p == '/' || *p == '\\') return 0;
  return strlen(s) < 200;
}
int sm_ps5save_restore_image(const sm_ps5save_request_t *r,
                             char *path, size_t cap) {
  if (!r || !path || !cap) return -1;
  int ps4 = strcmp(r->platform, "ps4") == 0;
  int prefixed = strncmp(r->image, "sdimg_", 6) == 0;
  const char *name = prefixed ? r->image + 6 : r->image;
  if ((!ps4 && strcmp(r->platform, "ps5") != 0) ||
      !hex_user(r->user, 8) || !hex_user(r->backup_user, 1) ||
      !title_id(r->title_id) ||
      (strcmp(r->version, "latest") && !sm_ps5save_legacy_date(r->version) &&
       !sm_ps5save_version_name(r->version)) ||
      !filename(r->slot) || !filename(name) ||
      strncmp(name, "sce_bu_", 7) == 0 || suffix(name, ".bin") ||
      suffix(name, ".ps5up-tmp") || suffix(name, ".smp-new") ||
      suffix(name, ".unsaved") ||
      (ps4 && !prefixed)) return -1;
  int n = snprintf(path, cap, "/user/home/%s/%s/%s/%s", r->user,
                   ps4 ? "savedata" : "savedata_prospero",
                   r->title_id, r->image);
  return n > 0 && (size_t)n < cap ? 0 : -1;
}
static int open_dir(int parent, const char *name) {
  return openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
}
/* Open one component at a time so even intermediate symlinks are rejected. */
int sm_ps5save_open_dir(int parent, const char *path) {
  int fd = open_dir(parent, ".");
  while (fd >= 0 && *path) {
    size_t n = strcspn(path, "/");
    char name[256];
    int next = -1;
    if (n && n < sizeof name) {
      memcpy(name, path, n);
      name[n] = 0;
      if (strcmp(name, ".") && strcmp(name, "..")) next = open_dir(fd, name);
      else errno = EINVAL;
    } else errno = EINVAL;
    int error = errno;
    close(fd);
    errno = error;
    fd = next;
    path += n;
    if (*path == '/') path++;
  }
  return fd;
}
int sm_ps5save_complete_version(int dir) {
  int fd = openat(dir, SM_PS5SAVE_COMPLETE, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) return 0;
  struct stat st;
  char magic[sizeof SM_PS5SAVE_COMPLETE_MAGIC - 1];
  int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
      st.st_size == sizeof magic && read(fd, magic, sizeof magic) == sizeof magic &&
      memcmp(magic, SM_PS5SAVE_COMPLETE_MAGIC, sizeof magic) == 0;
  close(fd);
  return ok;
}
static int read_stamp(int slot, struct stat *st) {
  int fd = openat(slot, ".image_stamp", O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) return -1;
  char magic[8];
  int ok = fstat(fd, st) == 0 && S_ISREG(st->st_mode) &&
      st->st_size == 64 && read(fd, magic, 8) == 8 &&
      memcmp(magic, "PS5IMG2\n", 8) == 0;
  close(fd);
  return ok ? 0 : -1;
}
int sm_ps5save_valid_stamp(int slot) {
  struct stat stamp;
  return read_stamp(slot, &stamp) == 0;
}
int sm_ps5save_open_slot(int volume, const sm_ps5save_request_t *r) {
  if (!r || sm_ps5save_restore_image(r, (char[512]){0}, 512) != 0)
    return -1;
  const int latest = strcmp(r->version, "latest") == 0;
  const int stored = sm_ps5save_version_name(r->version);
  char path[256];
  if (stored)
    snprintf(path, sizeof path, "PS5Save/" SM_PS5SAVE_VERSIONS "/%s/%s/%s/%s",
             r->platform, r->backup_user, r->title_id, r->version);
  else
    snprintf(path, sizeof path, "PS5Save/%s%s/saves/%s/%s/%s",
             latest ? "backup" : "backup_daily/", latest ? "" : r->version,
             r->platform, r->backup_user, r->title_id);
  int game = sm_ps5save_open_dir(volume, path);
  if (game < 0) return -1;
  int slot = !stored || sm_ps5save_complete_version(game)
      ? open_dir(game, r->slot) : -1;
  close(game);
  if (slot < 0) return -1;
  if ((latest || stored) && !sm_ps5save_valid_stamp(slot)) {
    close(slot);
    errno = EINVAL;
    return -1;
  }
  return slot;
}
static int same_entry(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
      a->st_size == b->st_size &&
      SM_STAT_MTIME(*a).tv_sec == SM_STAT_MTIME(*b).tv_sec &&
      SM_STAT_MTIME(*a).tv_nsec == SM_STAT_MTIME(*b).tv_nsec &&
      SM_STAT_CTIME(*a).tv_sec == SM_STAT_CTIME(*b).tv_sec &&
      SM_STAT_CTIME(*a).tv_nsec == SM_STAT_CTIME(*b).tv_nsec;
}
static int newer_than_stamp(const struct stat *entry, const struct stat *stamp) {
  struct timespec changed = SM_STAT_CTIME(*entry);
  struct timespec saved = SM_STAT_CTIME(*stamp);
  return changed.tv_sec > saved.tv_sec ||
      (changed.tv_sec == saved.tv_sec && changed.tv_nsec > saved.tv_nsec);
}
static int copy_file(int from, int to, const char *name, unsigned char *buf) {
  struct stat before, after;
  int in = openat(from, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if (in < 0) return -1;
  if (fstat(in, &before) != 0 || !S_ISREG(before.st_mode)) {
    close(in); return -1;
  }
  int out = openat(to, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0666);
  if (out < 0) { close(in); return -1; }
  off_t remain = before.st_size;
  int ok = 1;
  while (remain > 0) {
    ssize_t n = read(in, buf, remain < SM_SAVE_COPY_CHUNK ?
                       (size_t)remain : SM_SAVE_COPY_CHUNK);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { ok = 0; break; }
    ssize_t at = 0;
    while (at < n) {
      ssize_t w = write(out, buf + at, (size_t)(n - at));
      if (w < 0 && errno == EINTR) continue;
      if (w <= 0) { ok = 0; break; }
      at += w;
    }
    if (at != n) { ok = 0; break; }
    remain -= n;
  }
  if (fstat(in, &after) != 0 || !same_entry(&before, &after) ||
      fsync(out) != 0) ok = 0;
  if (close(out) != 0) ok = 0;
  close(in);
  return ok && remain == 0 ? 0 : -1;
}
typedef struct {
  unsigned char *buf;
  size_t files;
  const struct stat *stamp;
} slot_copy_t;
static int walk_slot(int source, int destination, unsigned depth, slot_copy_t *copy);
static int walk_entry(int source, int destination, unsigned depth,
                      slot_copy_t *copy, const char *name) {
  struct stat st;
  if (fstatat(source, name, &st, AT_SYMLINK_NOFOLLOW) != 0) return -1;
  if (destination >= 0 && copy->stamp && newer_than_stamp(&st, copy->stamp))
    return -1;
  if (S_ISDIR(st.st_mode)) {
    int sub = open_dir(source, name);
    if (sub < 0) return -1;
    int to = -1;
    if (destination >= 0 && mkdirat(destination, name, 0777) == 0)
      to = open_dir(destination, name);
    int rc = destination >= 0 && to < 0 ? -1 :
             walk_slot(sub, to, depth + 1, copy);
    if (to >= 0) close(to);
    close(sub);
    if (!rc && destination < 0) rc = unlinkat(source, name, AT_REMOVEDIR);
    return rc;
  }
  if (destination < 0) return unlinkat(source, name, 0);
  if (!S_ISREG(st.st_mode) ||
      copy_file(source, destination, name, copy->buf) != 0) return -1;
  copy->files++;
  return 0;
}
static int walk_slot(int source, int destination, unsigned depth, slot_copy_t *copy) {
  if (depth > SM_SAVE_TREE_DEPTH_MAX) return -1;
  struct stat before, after;
  if (destination >= 0 && fstat(source, &before) != 0) return -1;
  int fd = open_dir(source, ".");
  if (fd < 0) return -1;
  DIR *dir = fdopendir(fd);
  if (!dir) { close(fd); return -1; }
  int rc = 0;
  while (!rc) {
    errno = 0;
    const struct dirent *e = readdir(dir);
    if (!e) { if (errno) rc = -1; break; }
    const char *name = e->d_name;
    if (!strcmp(name, ".") || !strcmp(name, "..") ||
        (depth == 0 && !strcmp(name, "sce_sys"))) continue;
    if (destination >= 0 && (!strcmp(name, ".image_stamp") ||
                             !strcmp(name, ".ps5save-index"))) continue;
    if (destination >= 0 && suffix(name, ".part")) {
      if (copy->stamp) rc = -1;
      continue;
    }
    rc = walk_entry(source, destination, depth, copy, name);
  }
  closedir(dir);
  if (!rc && destination >= 0 &&
      (fstat(source, &after) != 0 || !same_entry(&before, &after))) rc = -1;
  return rc;
}
int sm_ps5save_copy_slot(int source, int destination, int latest) {
  struct stat stamp, after;
  if (latest && read_stamp(source, &stamp) != 0) return -1;
  int metadata = open_dir(destination, "sce_sys");
  if (metadata < 0) return -1; /* Not a valid decrypted mount. */
  close(metadata);
  slot_copy_t copy = { .buf = malloc(SM_SAVE_COPY_CHUNK),
                       .files = 0, .stamp = latest ? &stamp : NULL };
  if (!copy.buf) return -1;
  int rc = walk_slot(destination, -1, 0, &copy);
  if (!rc) rc = walk_slot(source, destination, 0, &copy);
  free(copy.buf);
  if (!rc && latest &&
      (read_stamp(source, &after) != 0 || !same_entry(&stamp, &after)))
    rc = -1;
  return copy.files ? rc : -1;
}
