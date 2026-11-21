/*
 * PS5Save restoration in ShadowMountPlus.
 *
 * The only writable PS5 save is an encrypted file under /user/home.
 * Always preserve that image before restoring, mount and edit a PRIVATE COPY,
 * and replace the original with an fsynced same-directory rename after umount.
 * Do not rename files between /mnt/ext1 and /user/home.
 *
 * Adapted from the user's PS5Upload-12.4.20-PS5Save-M2 fork, GPL-3.0-or-later.
 */
#include "sm_platform.h"
#include "sm_ps5save_restore.h"
#include "sm_game_lifecycle.h"
#include "sm_shellcore_service.h"
#include "sm_runtime.h"
#include "sm_log.h"
#include <pthread.h>
#include <dirent.h>
#include <sys/mount.h>

#define SMP_SAVE_ROOT "/data/shadowmount/save_restore"
#define SMP_SAVE_WORK SMP_SAVE_ROOT "/work"
#define SMP_SAVE_MOUNT SMP_SAVE_ROOT "/mount"
#define SMP_SAVE_BACKUP "PS5Save/smp_before_restore"
#define SMP_BUF_SIZE (256u * 1024u)

typedef struct { uint8_t reserved; char *budgetid; } SceFsMountSaveDataOpt;
typedef struct { uint8_t dummy; } SceFsUmountSaveDataOpt;
int sceFsInitMountSaveDataOpt(SceFsMountSaveDataOpt *opt);
int sceFsMountSaveData(SceFsMountSaveDataOpt *opt, const char *image,
                       const char *mount_point, uint8_t *key);
int sceFsInitUmountSaveDataOpt(SceFsUmountSaveDataOpt *opt);
int sceFsUmountSaveData(SceFsUmountSaveDataOpt *opt,
                        const char *mount_point, int handle, int ignore);

static pthread_mutex_t restore_lock = PTHREAD_MUTEX_INITIALIZER;

static int is_dir(const char *path) {
  struct stat st;
  return lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
}
static int ensure_dir(const char *path) {
  if (mkdir(path, 0770) == 0) return 0;
  return errno == EEXIST && is_dir(path) ? 0 : -1;
}
static int mounted_volume(void) {
  int fd = open(SM_PS5SAVE_VOLUME, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (fd < 0) return -1;
  struct statfs fs;
  if (fstatfs(fd, &fs) != 0 ||
      strcmp(fs.f_mntonname, SM_PS5SAVE_VOLUME) != 0) {
    close(fd);
    errno = ENODEV;
    return -1;
  }
  return fd;
}
static int busy_mountpoint(void) {
  struct stat mount, parent;
  if (stat(SMP_SAVE_MOUNT, &mount) != 0 ||
      stat(SMP_SAVE_ROOT, &parent) != 0) return 1;
  return mount.st_dev != parent.st_dev;
}
static int unchanged(const struct stat *a, const struct stat *b) {
#if defined(__FreeBSD__) || defined(__APPLE__)
#define SM_SAVE_MTIME(s) ((s).st_mtimespec)
#define SM_SAVE_CTIME(s) ((s).st_ctimespec)
#else
#define SM_SAVE_MTIME(s) ((s).st_mtim)
#define SM_SAVE_CTIME(s) ((s).st_ctim)
#endif
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
      a->st_size == b->st_size &&
      SM_SAVE_MTIME(*a).tv_sec == SM_SAVE_MTIME(*b).tv_sec &&
      SM_SAVE_MTIME(*a).tv_nsec == SM_SAVE_MTIME(*b).tv_nsec &&
      SM_SAVE_CTIME(*a).tv_sec == SM_SAVE_CTIME(*b).tv_sec &&
      SM_SAVE_CTIME(*a).tv_nsec == SM_SAVE_CTIME(*b).tv_nsec;
}
/* All writes are exclusive: stale staging files from an interrupted restore
 * must NEVER be silently truncated or reinterpreted as a fresh copy. */
static int copy_exclusive(const char *src, const char *dest) {
  int in = open(src, O_RDONLY | O_NOFOLLOW);
  if (in < 0) return -1;
  struct stat before, after;
  if (fstat(in, &before) || !S_ISREG(before.st_mode)) {
    close(in); errno = EINVAL; return -1;
  }
  int out = open(dest, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if (out < 0) { close(in); return -1; }
  uint8_t *buf = malloc(SMP_BUF_SIZE);
  int rc = buf ? 0 : -1;
  off_t remain = before.st_size;
  while (!rc && remain > 0) {
    ssize_t n = read(in, buf, remain < SMP_BUF_SIZE ? (size_t)remain : SMP_BUF_SIZE);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { rc = -1; break; }
    for (ssize_t at = 0; at < n;) {
      ssize_t w = write(out, buf + at, (size_t)(n - at));
      if (w < 0 && errno == EINTR) continue;
      if (w <= 0) { rc = -1; break; }
      at += w;
    }
    remain -= n;
  }
  if (!rc && (fstat(in, &after) != 0 ||
              !unchanged(&before, &after) ||
              fchmod(out, before.st_mode & 07777) != 0 ||
              fsync(out) != 0)) rc = -1;
  free(buf);
  if (close(out) != 0) rc = -1;
  close(in);
  if (rc) unlink(dest);
  return rc;
}
static int image_key(const char *image, const char *ps4_key,
                     bool ps4, uint8_t key[32]) {
  /* The pfsmgr ioctl writes its reply at +0x60; reserve 0x100 bytes. */
  uint8_t *data = calloc(1, 0x100);
  if (!data) return -1;
  int fd = open(ps4 ? ps4_key : image, O_RDONLY | O_NOFOLLOW);
  if (fd < 0) { free(data); return -1; }
  ssize_t size = ps4 ? read(fd, data, 0x60) :
                        pread(fd, data, 0x60, 0x800);
  close(fd);
  if (size != 0x60) { free(data); return -1; }
  int pfsmgr = open("/dev/pfsmgr", O_RDWR);
  if (pfsmgr < 0) { free(data); return -1; }
  int rc = ioctl(pfsmgr, 0xc0845302, data);
  close(pfsmgr);
  if (rc == 0) memcpy(key, data + 0x60, 32);
  memset(data, 0, 0x100);
  free(data);
  return rc == 0 ? 0 : -1;
}
static int mount_staged(const char *image, const char *key_path, bool ps4) {
  uint8_t key[32] = {0};
  if (image_key(image, key_path, ps4, key) != 0) return -1;
  SceFsMountSaveDataOpt opt = {0};
  if (sceFsInitMountSaveDataOpt(&opt) < 0) {
    memset(key, 0, sizeof(key)); return -1;
  }
  opt.budgetid = "system";
  /* All SMP threads block SIGPIPE from main onward. Only this Sony call
   * temporarily needs SIGPIPE's default disposition, per PS5Upload on 13.60. */
  sigset_t pipe_set;
  sigemptyset(&pipe_set);
  sigaddset(&pipe_set, SIGPIPE);
  void (*previous)(int) = signal(SIGPIPE, SIG_DFL);
  (void)pthread_sigmask(SIG_UNBLOCK, &pipe_set, NULL);
  int rc = sceFsMountSaveData(&opt, image, SMP_SAVE_MOUNT, key);
  (void)pthread_sigmask(SIG_BLOCK, &pipe_set, NULL);
  (void)signal(SIGPIPE, previous);
  memset(key, 0, sizeof(key));
  return rc < 0 ? -1 : 0;
}
static int unmount_staged(void) {
  SceFsUmountSaveDataOpt opt = {0};
  if (sceFsInitUmountSaveDataOpt(&opt) < 0) return -1;
  int rc = sceFsUmountSaveData(&opt, SMP_SAVE_MOUNT, 0, 0);
  sync();
  if (rc < 0 || busy_mountpoint()) return -1;
  return 0;
}
static int game_busy(const char *title) {
  /* Conservative: no other game's write/exit may race a save restore. */
  return runtime_sleep_mode_active() ||
      sm_game_lifecycle_has_active_game() ||
      sm_shellcore_title_is_protected(title);
}
static int ps4_key_path(const char *image, char *out, size_t cap) {
  const char *base = strrchr(image, '/');
  if (!base || strncmp(base + 1, "sdimg_", 6)) return -1;
  size_t parent = (size_t)(base - image);
  int n = snprintf(out, cap, "%.*s/%s.bin", (int)parent, image, base + 7);
  return n > 0 && (size_t)n < cap ? 0 : -1;
}
static int backup_current(int volume, const sm_ps5save_request_t *r,
                          const char *image, const char *key,
                          char *backup_out, size_t cap) {
  char home[512], user[512], title[512];
  snprintf(home, sizeof home, "%s/" SMP_SAVE_BACKUP, SM_PS5SAVE_VOLUME);
  snprintf(user, sizeof user, "%s/%s", home, r->user);
  snprintf(title, sizeof title, "%s/%s", user, r->title_id);
  /* Reverify that volume has not been detached before writing. */
  struct stat fs;
  if (fstat(volume, &fs) != 0 ||
      ensure_dir(home) || ensure_dir(user) || ensure_dir(title)) return -1;
  time_t when = time(NULL);
  int n = snprintf(backup_out, cap, "%s/%lld-%ld-%s", title,
                   (long long)when, (long)getpid(), r->image);
  if (n <= 0 || (size_t)n >= cap || copy_exclusive(image, backup_out)) return -1;
  if (key) {
    char to_key[1100];
    if (ps4_key_path(backup_out, to_key, sizeof to_key) != 0 ||
        copy_exclusive(key, to_key) != 0) return -1;
  }
  return 0;
}
int sm_ps5save_restore(const sm_ps5save_request_t *r, const char **reason) {
  const char *why = "unknown_error";
  char image[1024], key[1024] = {0}, backup[1100] = {0};
  char work[1024] = {0}, work_key[1024] = {0}, temp[1100] = {0};
  int volume = -1, slot = -1, fd = -1;
  bool mounted = false;
  bool ps4 = r && strcmp(r->platform, "ps4") == 0;
  int rc = -1;
  if (reason) *reason = "invalid_request";
  if (sm_ps5save_restore_image(r, image, sizeof image) != 0) return -1;
  if (pthread_mutex_trylock(&restore_lock) != 0) {
    if (reason) *reason = "restore_busy";
    return -1;
  }
  if (game_busy(r->title_id)) { why = "game_running"; goto done; }
  volume = mounted_volume();
  if (volume < 0) { why = "m2_not_mounted"; goto done; }
  slot = sm_ps5save_open_slot(volume, r);
  if (slot < 0) { why = "backup_missing_or_incomplete"; goto done; }
  struct stat before, after;
  if (lstat(image, &before) != 0 || !S_ISREG(before.st_mode)) {
    why = "target_missing"; goto done;
  }
  if (ps4 && ps4_key_path(image, key, sizeof key) != 0) {
    why = "target_invalid"; goto done;
  }
  if (ensure_dir(SMP_SAVE_ROOT) || ensure_dir(SMP_SAVE_WORK) ||
      ensure_dir(SMP_SAVE_MOUNT) || busy_mountpoint()) {
    why = "mount_busy_or_orphaned"; goto done;
  }
  /* Critical: never modify live save without a separately fsynced backup. */
  if (backup_current(volume, r, image, ps4 ? key : NULL,
                     backup, sizeof backup) != 0) {
    why = "pre_restore_backup_failed"; goto done;
  }
  snprintf(work, sizeof work, SMP_SAVE_WORK "/%s", r->image);
  if (copy_exclusive(image, work) != 0) {
    why = "staging_failed_or_stale_file"; goto done;
  }
  if (ps4) {
    if (ps4_key_path(work, work_key, sizeof work_key) != 0 ||
        copy_exclusive(key, work_key) != 0) {
      why = "staging_key_failed"; goto done;
    }
  }
  if (mount_staged(work, work_key, ps4) != 0) {
    why = "save_mount_failed"; goto done;
  }
  mounted = true;
  fd = open(SMP_SAVE_MOUNT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (fd < 0 || sm_ps5save_copy_slot(slot, fd,
                                   strcmp(r->version, "latest") == 0) != 0) {
    why = "slot_copy_failed"; goto done;
  }
  if (game_busy(r->title_id) || lstat(image, &after) != 0 ||
      !unchanged(&before, &after)) {
    why = "game_running_or_target_changed"; goto done;
  }
  if (fd >= 0) { close(fd); fd = -1; }
  /* Commit ONLY after the Sony volume flushes and detaches successfully. */
  if (unmount_staged() != 0) {
    why = "unmount_failed_staging_preserved"; goto done;
  }
  mounted = false;
  if (game_busy(r->title_id) || lstat(image, &after) != 0 ||
      !unchanged(&before, &after)) {
    why = "target_changed_before_commit"; goto done;
  }
  if (snprintf(temp, sizeof temp, "%s.smp-new", image) >= (int)sizeof temp ||
      copy_exclusive(work, temp) != 0) {
    why = "writeback_stage_failed"; goto done;
  }
  if (game_busy(r->title_id) || lstat(image, &after) != 0 ||
      !unchanged(&before, &after)) {
    why = "target_changed_before_rename"; goto done;
  }
  if (rename(temp, image) != 0) {
    why = "atomic_replace_failed"; goto done;
  }
  temp[0] = '\0';
  rc = 0;
  why = "ok";
done:
  if (fd >= 0) close(fd);
  if (mounted) {
    /* Failure never permits write-back of a partial temp image. */
    if (unmount_staged() != 0) {
      why = "unmount_failed_staging_preserved";
      /* Never unlink a file still used by the mounted filesystem. */
      work[0] = '\0';
      work_key[0] = '\0';
    } else mounted = false;
  }
  if (temp[0]) unlink(temp);
  if (work_key[0]) unlink(work_key);
  if (work[0]) unlink(work);
  if (slot >= 0) close(slot);
  if (volume >= 0) close(volume);
  pthread_mutex_unlock(&restore_lock);
  log_debug("  [SAVES] PS5Save restore title=%s user=%s status=%s pre_backup=%s",
            r->title_id, r->user, why, backup[0] ? backup : "(none)");
  if (reason) *reason = why;
  return rc;
}
