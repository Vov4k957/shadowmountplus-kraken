/* Copyright (C) 2026

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

/**
 * PS5Save v2 M.2 backup engine, integrated into ShadowMountPlus.
 * Adaptation: the worker keeps an open directory on M.2, shares the
 * save-operation lock with restore, and reports status to the SM+ UI.
 *
 * M.2 adaptation (2026-11-14): verify the mounted SSD and use its open
 * directory as the base for all backup paths during each pass.
 *
 * Reads /mnt/ext1/PS5Save/backup.conf and copies the listed files to
 * /mnt/ext1/PS5Save/backup/<original path>:
 *
 *   /data/PCSX2/Mcd001.ps2        one file
 *   /data/porpoise/saves/<star>   every file and folder below, recursively
 *   backup_interval_seconds=60      seconds between backups (default 60)
 *   backup_ps4_saves=true           enable decrypted PS4 saves (default false)
 *   backup_ps5_saves=true           enable decrypted PS5 saves (default false)
 *   max_title_size_mb=4096          size limit for all save images of one title
 *                                  in decimal MB; default 4096 = 4.096GB
 *   backup_trophies=true            copy local PS4/PS5 trophy files (default true)
 *
 * Save versions are committed per game and profile. Only changed games produce
 * new versions, with up to three complete game copies retained.
 *
 * Plain files larger than 100MB are skipped. A game's saves are backed up
 * completely or not at all: the size of the whole title id folder is checked
 * against max_title_size_mb, and the M.2 and internal storage are checked for
 * free space, before anything is mounted. The payload keeps running in the
 * background and only copies what changed.
 *
 * PS4/PS5 saves are encrypted images. For each image that changed, a COPY of
 * the image is mounted (the original is only ever read), the decrypted files
 * are copied to /mnt/ext1/PS5Save/backup_versions/..., and the image is unmounted again.
 * A title is deferred while that same title is running, suspended or still
 * sandbox-mounted. Other titles may be backed up during gameplay. Activity is
 * checked before mounting and during copying; unknown activity fails closed.
 * Deferred titles are retried after closure, independently of the interval.
 *
 * Save mounting is based on the Playstation-5-Save-Mounter payload by n0llptr
 * (GPLv3), which in turn builds on research by cow and the garlic-savemgr
 * project by earthonion.
 **/

#include "sm_ps5save_backup.h"
#include "sm_ps5save_restore.h"
#include "sm_filesystem.h"
#include "sm_log.h"
#include "sm_runtime.h"
#include "sm_paths.h"
#include "sm_scanner.h"
#include "sm_shellcore_service.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef BACKUP_HOST_TEST
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#else
#include <sys/statfs.h>
#include <sys/statvfs.h>
#endif

#include <ps5/kernel.h>


#ifndef M2_MOUNT
#define M2_MOUNT      SM_PS5SAVE_VOLUME
#endif
#ifndef M2_BACKUP_DIR
#define M2_BACKUP_DIR "PS5Save"
#endif
#ifndef USER_ROOT
#define USER_ROOT     "/user"
#endif
#ifndef HOME_ROOT
#define HOME_ROOT     USER_ROOT "/home"
#endif
#ifndef TMP_DIR
#define TMP_DIR       "/data/save_files"
#endif
#ifndef PFS_ROOT
#define PFS_ROOT      "/mnt/pfs"
#endif
#ifndef PFSMGR_DEV
#define PFSMGR_DEV    "/dev/pfsmgr"
#endif

#define CONF_PATH     "backup.conf"
#define BACKUP_ROOT   "backup"
#define LAST_COPY_PATH ".smp-last-copy"
#define TMP_IMG       TMP_DIR "/_backup_tmp_image"
#define MOUNT_POINT   PFS_ROOT "/savebackup_tmp"
#define BYTES_PER_MB  1000000ULL /* decimal megabytes */
#define MAX_FILE_SZ   (100ULL * BYTES_PER_MB)
#define DEF_GAME_MB   4096    /* default limit: all saves of one title id, in MB */
#ifndef MIN_GAME_MB
#define MIN_GAME_MB   64
#endif
#define MAX_GAME_MB   65536
#define MAX_IMAGES    512     /* save images per title id */
#define SPACE_MARGIN  (64ULL * 1024ULL * 1024ULL)
#define COPY_BUF_SZ   (1024 * 1024)

#define DEF_INTERVAL  60      /* seconds between backups */
#ifndef MIN_INTERVAL
#define MIN_INTERVAL  30
#endif
#define MAX_INTERVAL  (SM_PS5SAVE_MAX_INTERVAL_MINUTES * 60L)
#ifndef SLICE_SEC
#define SLICE_SEC     10      /* wake-up granularity while waiting */
#endif
#ifndef LOCK_PORT
#define LOCK_PORT     9055    /* loopback port reserved by the standalone utility */
#endif
#define MAX_SEEN      256
#define SAVE_AUTHID   0x4800000000000010ULL

#ifndef GAME_CHECK_SEC
#define GAME_CHECK_SEC 1.0    /* how often the game check is repeated while mounted */
#endif


_Static_assert(offsetof(app_info_t, title_id) == 0x10, "Incorrect app-info title offset");

/* save data mounting, from libSceFsInternalForVsh (see Save Mounter) */
typedef struct { uint8_t reserved; char *budgetid; } MountOpt;
typedef struct { uint8_t dummy; } UmountOpt;

int sceFsInitMountSaveDataOpt(MountOpt *opt);
int sceFsMountSaveData(MountOpt *opt, const char *path, const char *mount,
                       uint8_t *key);
int sceFsInitUmountSaveDataOpt(UmountOpt *opt);
int sceFsUmountSaveData(UmountOpt *opt, const char *mount, int handle,
                        int ignore);


typedef struct backup_stats {
  uint64_t bytes;
  unsigned copied;
  unsigned unchanged;
  unsigned skipped;
  unsigned failed;
} backup_stats_t;

typedef enum { SV_OK, SV_FAILED, SV_GAME } sv_result_t;


static char *g_buf;
static int g_backup_directory = -1;
static atomic_bool g_stopping = false;
static pthread_mutex_t g_status_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_save_io_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_backup_wake = PTHREAD_COND_INITIALIZER;
static pthread_t g_backup_thread;
static bool g_worker_started;
static bool g_manual_requested;
static unsigned g_schedule_revision;
static double g_schedule_changed;
static int g_restore_port = -1;
static sm_ps5save_backup_status_t g_backup_status = {
  .state = "waiting", .enabled = true, .interval_seconds = DEF_INTERVAL
};

#ifndef BACKUP_PAUSE_FILE
#define BACKUP_PAUSE_FILE LOG_DIR "/save-backup.disabled"
#endif

static bool
interrupted(void) {
  return atomic_load(&g_stopping) || should_stop_requested() || runtime_sleep_mode_active();
}

/* Relative paths keep the original backup/index format. Only this worker
 * uses the open M.2 directory; the SM+ process's cwd never changes. */
static FILE *
backup_fopen(const char *path, const char *mode) {
  const bool reading = mode[0] == 'r';
  const int fd = openat(g_backup_directory, path,
      (reading ? O_RDONLY | O_NONBLOCK : O_WRONLY | O_CREAT | O_TRUNC) | O_NOFOLLOW,
      0666);
  if(fd < 0) return NULL;
  FILE *file = fdopen(fd, mode);
  if(!file) close(fd);
  return file;
}

static DIR *
backup_opendir(const char *path) {
  int fd = openat(g_backup_directory, path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if(fd < 0) return NULL;
  DIR *dir = fdopendir(fd);
  if(!dir) close(fd);
  return dir;
}

static int
sync_backup_directory(int fd) {
  if(fsync(fd) == 0) return 0;
  if(errno != EINVAL && errno != EOPNOTSUPP) return -1;
  sync();
  return 0;
}

static int
sync_backup_path(const char *path) {
  int fd = sm_ps5save_open_dir(g_backup_directory, path);
  if(fd < 0) return -1;
  int rc = sync_backup_directory(fd);
  close(fd);
  return rc;
}

static void
backup_preserve_time(const char *path, time_t mtime) {
  const struct timespec times[2] = {{mtime, 0}, {mtime, 0}};
  (void)utimensat(g_backup_directory, path, times, 0);
}
static long g_interval = DEF_INTERVAL;
static int g_last_failed = 0;
static char *g_seen[MAX_SEEN];
static int g_nseen = 0;

static uint64_t g_max_game = DEF_GAME_MB * BYTES_PER_MB;
static uint64_t g_file_cap = MAX_FILE_SZ;   /* per-file limit, 0 = none */
static int g_trophies = 1;
static int g_ps4saves = 0;
static int g_ps5saves = 0;
static int g_need_cleanup = 1;
static int g_mount_stuck = 0;
static int g_watch_game = 0;      /* protect the currently mounted title */
static int g_game_abort = 0;      /* abort this save image only */
static int g_backup_busy = 0;     /* one activity log entry per copying pass */
static int g_start_logged = 0;
static double g_last_watch = 0;
static char g_abort_why[192];


static void logq(const char *fmt, ...);

#include "../vendor/ps5save/backup_progress.h"

static void
backup_activity_begin(void) {
  if(g_backup_busy) return;
  g_backup_busy = 1;
  logq("Backing up saves to M.2");
  progress_start();
}

/**
 * Write backup diagnostics to the ShadowMountPlus log.
 **/
static void
logq(const char *fmt, ...) {
  char msg[2048];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(msg, sizeof msg, fmt, ap);
  va_end(ap);

  log_debug("  [SAVES] %s", msg);
}


/**
 * Returns non-zero if the path was reported before; remembers it otherwise.
 * Used so that a permanently oversized file is not announced every cycle.
 **/
static int
seen_before(const char *path) {
  for(int i = 0; i < g_nseen; i++) {
    if(!strcmp(g_seen[i], path)) {
      return 1;
    }
  }
  if(g_nseen < MAX_SEEN) {
    g_seen[g_nseen++] = strdup(path);
  }
  return 0;
}


static void
format_size(uint64_t bytes, char *out, size_t len) {
  if(bytes >= 1000ULL * 1000ULL * 1000ULL) {
    snprintf(out, len, "%.1fGB", (double)bytes / (1000.0 * 1000.0 * 1000.0));
  } else if(bytes >= 10ULL * 1000ULL * 1000ULL) {
    snprintf(out, len, "%.0fMB", (double)bytes / (1000.0 * 1000.0));
  } else if(bytes >= 1000ULL * 1000ULL) {
    snprintf(out, len, "%.1fMB", (double)bytes / (1000.0 * 1000.0));
  } else if(bytes >= 1000ULL) {
    snprintf(out, len, "%.0fkB", (double)bytes / 1000.0);
  } else {
    snprintf(out, len, "%lluB", (unsigned long long)bytes);
  }
}


static double
now_seconds(void) {
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}


static time_t
wall_clock(void) {
  struct timespec ts;

#ifdef BACKUP_HOST_TEST
  /* the host test can set the clock through a file */
  const char *tf = getenv("TEST_NOW_FILE");
  if(tf) {
    FILE *fp = fopen(tf, "r");
    long long v;

    if(fp) {
      int ok = fscanf(fp, "%lld", &v) == 1;
      fclose(fp);
      if(ok) {
        return (time_t)v;
      }
    }
  }
#endif

  clock_gettime(CLOCK_REALTIME, &ts);
  return ts.tv_sec;
}


/**
 * mkdir -p
 **/
static int
mkdir_p(const char *path) {
  char tmp[PATH_MAX];
  size_t len;

  len = snprintf(tmp, sizeof tmp, "%s", path);
  if(len == 0 || len >= sizeof tmp) {
    return -1;
  }

  for(char *p = tmp + 1; *p; p++) {
    if(*p == '/') {
      *p = 0;
      if(mkdirat(g_backup_directory, tmp, 0777) && errno != EEXIST) {
        return -1;
      }
      if(tmp[0] != '/') {
        int fd = openat(g_backup_directory, tmp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if(fd < 0) return -1;
        close(fd);
      }
      *p = '/';
    }
  }

  if(mkdirat(g_backup_directory, tmp, 0777) && errno != EEXIST) {
    return -1;
  }

  if(tmp[0] == '/') return 0;
  int fd = openat(g_backup_directory, tmp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if(fd < 0) return -1;
  close(fd);
  return 0;
}


/**
 * Free space (bytes) on the file system holding path.
 **/
static uint64_t
fs_free(const char *path, const char *test_env) {
  struct statfs sf;

#ifdef BACKUP_HOST_TEST
  const char *o = getenv(test_env);
  if(o) {
    return strtoull(o, NULL, 10);
  }
#else
  (void)test_env;
#endif

  if((path ? statfs(path, &sf) : fstatfs(g_backup_directory, &sf)) ||
     (int64_t)sf.f_bavail <= 0) {
    return 0;
  }
  return (uint64_t)sf.f_bavail * (uint64_t)sf.f_bsize;
}


#define backup_free() fs_free(NULL, "TEST_M2_FREE")
#define data_free()   fs_free(TMP_DIR, "TEST_DATA_FREE")


/**
 * Total size of all regular files below path.
 **/
static void game_watch(void);

static uint64_t
dir_size(const char *path) {
  char sub[PATH_MAX];
  struct dirent *dp;
  struct stat st;
  uint64_t total = 0;
  DIR *dir;

  if(!(dir = backup_opendir(path))) {
    return 0;
  }
  while((dp = readdir(dir))) {
    game_watch();
    if(g_watch_game && g_game_abort) break;
    if(!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) {
      continue;
    }
    if(snprintf(sub, sizeof sub, "%s/%s", path, dp->d_name) >= (int)sizeof sub ||
       fstatat(g_backup_directory, sub, &st, AT_SYMLINK_NOFOLLOW)) {
      continue;
    }
    if(S_ISDIR(st.st_mode)) {
      total += dir_size(sub);
    } else if(S_ISREG(st.st_mode)) {
      total += st.st_size;
    }
  }
  closedir(dir);
  return total;
}


/* ------------------------------------------------------------------------
 * Game detection
 * ---------------------------------------------------------------------- */

#include "../vendor/ps5save/title_activity.h"


/**
 * Called regularly while an image is copied or mounted. If its title appears,
 * g_game_abort is set and save-image copy loops stop as soon as possible.
 * Ordinary configured files are independent of game detection.
 **/
static void
game_watch(void) {
  char why[160];
  double t;

  if(g_watch_game && interrupted()) {
    g_game_abort = 1;
    return;
  }
  if(!g_watch_game || g_game_abort) {
    return;
  }

  t = now_seconds();
  if(t - g_last_watch < GAME_CHECK_SEC) {
    return;
  }
  g_last_watch = t;

  if(title_blocked(g_watch_title, why, sizeof why, 0)) {
    g_game_abort = 1;
    snprintf(g_abort_why, sizeof g_abort_why, "%s", why);
  }
}


#include "../vendor/ps5save/change_index.h"


/* ------------------------------------------------------------------------
 * Plain file backup
 * ---------------------------------------------------------------------- */

/**
 * Copy a single file from src to dst. The data is written to a temporary file
 * first, so that an interrupted copy never
 * destroys the previous good backup.
 **/
static void
backup_file(const char *src, const char *dst, const struct stat *st,
            backup_stats_t *stats) {
  char tmp[PATH_MAX];
  char dir[PATH_MAX];
  const char *label = dst;
  struct stat after;
  char *slash;
  ssize_t n = -1;
  int in = -1;
  int out = -1;
  int ok = 0;
  int aborted = 0;
  unsigned reads = 0;

  int progress_started = 0;
  if(g_progress_planning) {
    if((!g_file_cap || (uint64_t)st->st_size <= g_file_cap) &&
       !file_current(dst, st))
      progress_plan(1);
    return;
  }

  /* per-file limit; not applied inside game saves, which are judged per game */
  if(g_file_cap && (uint64_t)st->st_size > g_file_cap) {
    if(!seen_before(label)) {
      logq("Abnormal size of %s; skipping backup", label);
    }
    stats->skipped++;
    return;
  }

  game_watch();
  if(g_watch_game && g_game_abort) {
    return;
  }

  tmp[0] = 0;
  if(snprintf(tmp, sizeof tmp, "%s.part", dst) >= (int)sizeof tmp) {
    tmp[0] = 0;
    goto done;
  }

  /* Exact source and destination metadata cached after a successful copy. */
  if(!g_progress_image && file_current(dst, st)) {
    stats->unchanged++;
    if(g_progress_image) progress_advance(st->st_size);
    return;
  }

  if(backup_free() < (uint64_t)st->st_size + SPACE_MARGIN) {
    logq("Failed to backup %s (not enough space on M.2)", label);
    stats->failed++;
    return;
  }

  snprintf(dir, sizeof dir, "%s", dst);
  if((slash = strrchr(dir, '/')) && slash != dir) {
    *slash = 0;
    if(mkdir_p(dir)) {
      goto done;
    }
  }

  if((in = openat(g_backup_directory, src, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)) < 0 ||
     fstat(in, &after) || !source_same(st, &after)) {
    goto done;
  }
  if(!g_progress_image) {
    progress_begin(st->st_size);
    progress_started = 1;
  }
  backup_activity_begin();
  if(unlinkat(g_backup_directory, tmp, 0) && errno != ENOENT) {
    tmp[0] = 0;
    goto done;
  }
  if((out = openat(g_backup_directory, tmp,
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0666)) < 0) {
    goto done;
  }

  while(!interrupted() && (n = read(in, g_buf, COPY_BUF_SZ)) > 0) {
    char *p = g_buf;
    while(n > 0) {
      ssize_t w = write(out, p, n);
    if(w <= 0) {
        if(errno == EINTR) {
          continue;
        }
        goto done;
      }
      progress_advance(w);
      p += w;
      n -= w;
    }
    if(++reads) {
      game_watch();
      if(g_watch_game && g_game_abort) {
        aborted = 1;
        goto done;
      }
    }
  }
  if(n < 0 || interrupted()) {
    goto done;
  }

  if(fstat(in, &after) || !source_same(st, &after)) {
    logq("Source changed during copy: %s", src);
    goto done;
  }
  if(fsync(out)) {
    goto done;
  }
  if(close(out)) {
    out = -1;
    goto done;
  }
  out = -1;

  /* keep the source mtime so the next cycle can detect "unchanged" */
  backup_preserve_time(tmp, st->st_mtime);

  if(renameat(g_backup_directory, tmp, g_backup_directory, dst)) {
    goto done;
  }

  if(!g_progress_image) index_update(dst, st);
  ok = 1;

done:
  if(progress_started) progress_finish();
  if(in >= 0) {
    close(in);
  }
  if(out >= 0) {
    close(out);
  }

  if(ok) {
    stats->copied++;
    stats->bytes += st->st_size;
  } else {
    if(tmp[0]) {
      unlinkat(g_backup_directory, tmp, 0);
    }
    if(!aborted) {
      logq("Failed to backup %s", label);
      stats->failed++;
    }
  }
}


/**
 * Back up everything below the directory src into dst, recursively.
 **/
static void
backup_tree(const char *src, const char *dst, backup_stats_t *stats) {
  char spath[PATH_MAX];
  char dpath[PATH_MAX];
  struct dirent *dp;
  struct stat st;
  DIR *dir;

  if((!g_progress_planning && g_progress_image && mkdir_p(dst)) ||
     !(dir = backup_opendir(src))) {
    logq("Failed to backup %s", dst);
    stats->failed++;
    return;
  }

  while(!interrupted() && !(g_watch_game && g_game_abort)) {
    errno = 0;
    dp = readdir(dir);
    if(!dp) {
      if(errno) stats->failed++;
      break;
    }
    if(!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) {
      continue;
    }

    if(snprintf(spath, sizeof spath, "%s/%s", src, dp->d_name) >= (int)sizeof spath ||
       snprintf(dpath, sizeof dpath, "%s/%s", dst, dp->d_name) >= (int)sizeof dpath) {
      stats->failed++;
      continue;
    }

    if(lstat(spath, &st)) {
      stats->failed++;
      continue;
    }

    if(S_ISDIR(st.st_mode)) {
      backup_tree(spath, dpath, stats);
    } else if(S_ISREG(st.st_mode)) {
      backup_file(spath, dpath, &st, stats);
    }
    /* symlinks and special files are ignored */
  }

  closedir(dir);
  if(g_progress_image && !interrupted() && !g_game_abort && sync_backup_path(dst))
    stats->failed++;
}


/* ------------------------------------------------------------------------
 * PS4 / PS5 save images
 * ---------------------------------------------------------------------- */

/* Configuration booleans accept exactly the documented lowercase tokens. */
static int
parse_bool(const char *value, int *out) {
  if(!strcmp(value, "true")) {
    *out = 1;
    return 1;
  }
  if(!strcmp(value, "false")) {
    *out = 0;
    return 1;
  }
  logq("Invalid boolean setting: %s (expected false or true)", value);
  return 0;
}

static int
is_hex_name(const char *s) {
  size_t len = strlen(s);

  if(len == 0 || len > 8) {
    return 0;
  }
  for(size_t i = 0; i < len; i++) {
    if(!isxdigit((unsigned char)s[i])) {
      return 0;
    }
  }
  return 1;
}


/**
 * Free space check for the temporary image copy in internal storage.
 **/
static int
enough_space(uint64_t need) {
  mkdir_p(TMP_DIR);
  return data_free() >= need;
}


/**
 * Copy src to dst (plain, no temp file). Returns 0 on success, -1 on error
 * and -2 if the copy was stopped because a game appeared.
 **/
static int
copy_plain(const char *src, const char *dst) {
  unsigned reads = 0;
  int rc = -1;
  ssize_t n = -1;
  int in;
  int out;

  if((in = openat(g_backup_directory, src, O_RDONLY)) < 0) {
    return -1;
  }
  backup_activity_begin();
  if((out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0777)) < 0) {
    close(in);
    return -1;
  }

  while(!interrupted() && (n = read(in, g_buf, COPY_BUF_SZ)) > 0) {
    char *p = g_buf;
    while(n > 0) {
      ssize_t w = write(out, p, n);
    if(w <= 0) {
        if(errno == EINTR) {
          continue;
        }
        goto done;
      }
      progress_advance(w);
      p += w;
      n -= w;
    }
    if(++reads) {
      game_watch();
      if(g_game_abort) {
        rc = -2;
        goto done;
      }
    }
  }
  if(n == 0 && !interrupted()) {
    rc = 0;
  }

done:
  close(in);
  if(close(out)) {
    rc = rc ? rc : -1;
  }
  return rc;
}


/**
 * Decrypt the sealed save key (0x60 bytes) through the pfsmgr device.
 **/
static int
decrypt_key(const uint8_t *sealed, uint8_t key[0x20]) {
  uint8_t *data;
  int fd;
  int rc;

  if(!(data = calloc(1, 0x100))) {
    return -1;
  }
  memcpy(data, sealed, 0x60);

  if((fd = open(PFSMGR_DEV, O_RDWR)) < 0) {
    free(data);
    return -1;
  }
  rc = ioctl(fd, 0xc0845302, data);
  close(fd);

  if(rc >= 0) {
    memcpy(key, data + 0x60, 0x20);
  }
  free(data);
  return rc < 0 ? -1 : 0;
}

/* Retain PS5Save's identity only while calling the save filesystem.
 * Pause ShellCore/scanner mutations while the process credentials change. */
static bool
begin_save_call(uint64_t *authid) {
  if(!sm_scanner_try_begin_external_mutation()) return false;
  if(!sm_shellcore_try_begin_external_mutation()) {
    sm_scanner_end_external_mutation();
    return false;
  }
  *authid = kernel_get_ucred_authid(-1);
  if(*authid && kernel_set_ucred_authid(-1, SAVE_AUTHID) == 0) return true;
  sm_shellcore_end_external_mutation();
  sm_scanner_end_external_mutation();
  return false;
}

static void
end_save_call(uint64_t authid) {
  const int error = errno;
  if(kernel_set_ucred_authid(-1, authid) != 0)
    logq("Could not restore SM+ credentials after a save operation");
  sm_shellcore_end_external_mutation();
  sm_scanner_end_external_mutation();
  errno = error;
}

static int
mount_save(MountOpt *opt, const char *path, uint8_t *key) {
  uint64_t authid;
  if(!begin_save_call(&authid)) {
    errno = EBUSY;
    return -1;
  }
  sigset_t pipe_set;
  sigemptyset(&pipe_set);
  sigaddset(&pipe_set, SIGPIPE);
  void (*previous)(int) = signal(SIGPIPE, SIG_DFL);
  (void)pthread_sigmask(SIG_UNBLOCK, &pipe_set, NULL);
  const int result = sceFsMountSaveData(opt, path, MOUNT_POINT, key);
  (void)pthread_sigmask(SIG_BLOCK, &pipe_set, NULL);
  (void)signal(SIGPIPE, previous);
  end_save_call(authid);
  return result;
}

static int
detach_save(void) {
  uint64_t authid;
  if(!begin_save_call(&authid)) {
    errno = EBUSY;
    return -1;
  }
  UmountOpt opt = {0};
  sceFsInitUmountSaveDataOpt(&opt);
  const int result = sceFsUmountSaveData(&opt, MOUNT_POINT, 0, 0);
  end_save_call(authid);
  return result;
}


/**
 * Unmount the temporary save mount, retrying a few times.
 **/
static int
unmount_save(void) {
  int ret = -1;

  for(int i = 0; i < 5; i++) {
    if((ret = detach_save()) >= 0) {
      sync();
      return 0;
    }
    sleep(1);
  }

  logq("umount failed (0x%08x)", ret);
  return -1;
}


/**
 * Remove anything a previous (killed) instance may have left behind.
 **/
static void
cleanup_stale(void) {
  (void)detach_save();
  if(rmdir(MOUNT_POINT) && errno != ENOENT) {
    g_mount_stuck = 1;
    return;
  }
  g_mount_stuck = 0;
  unlink(TMP_IMG);
}


static bool same_backup_volume(int fd);

static int
copy_version_file(const char *src, const char *dst, const struct stat *st) {
  ssize_t n = -1;
  int rc = -1;
  int in;
  int out;

  if((in = openat(g_backup_directory, src, O_RDONLY | O_NOFOLLOW)) < 0) {
    return -1;
  }
  if((out = openat(g_backup_directory, dst,
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0666)) < 0) {
    close(in);
    return -1;
  }

  while(!interrupted() && (n = read(in, g_buf, COPY_BUF_SZ)) > 0) {
    char *p = g_buf;
    while(n > 0) {
      ssize_t w = write(out, p, n);
    if(w <= 0) {
        if(errno == EINTR) {
          continue;
        }
        goto done;
      }
      p += w;
      n -= w;
    }
  }
  struct stat after;
  if(n == 0 && !interrupted() && !fstat(in, &after) &&
     source_same(st, &after) && !fsync(out)) {
    rc = 0;
  }

done:
  close(in);
  if(close(out)) {
    rc = -1;
  }
  if(!rc) {
    backup_preserve_time(dst, st->st_mtime);
  }
  return rc;
}


#include "../vendor/ps5save/save_versions.h"

static int
stamp_current(const char *dst_dir, const struct stat *img) {
  char path[PATH_MAX];
  file_signature_t stored, current = file_signature(img);
  snprintf(path, sizeof path, "%s/.image_stamp", dst_dir);
  FILE *f = backup_fopen(path, "rb");
  if(!f) return 0;
  char magic[8];
  int ok = fread(magic, 1, 8, f) == 8 && !memcmp(magic, "PS5IMG2\n", 8) &&
           fread(&stored, 1, sizeof stored, f) == sizeof stored &&
           !memcmp(&stored, &current, sizeof stored);
  fclose(f);
  return ok;
}

static int
stamp_write(const char *dst_dir, const file_signature_t *sig) {
  char path[PATH_MAX], part[PATH_MAX];
  snprintf(path, sizeof path, "%s/.image_stamp", dst_dir);
  snprintf(part, sizeof part, "%s.part", path);
  FILE *f = backup_fopen(part, "wb");
  if(!f) return -1;
  int ok = fwrite("PS5IMG2\n", 1, 8, f) == 8 &&
           fwrite(sig, 1, sizeof *sig, f) == sizeof *sig;
  if(fflush(f) || fsync(fileno(f))) ok = 0;
  if(fclose(f)) ok = 0;
  if(ok && !renameat(g_backup_directory, part, g_backup_directory, path))
    return sync_backup_path(dst_dir);
  unlinkat(g_backup_directory, part, 0);
  return -1;
}


/**
 * Back up one save image. The original is only read: a copy is mounted.
 **/
static sv_result_t
backup_save_image(const char *title, const char *tdir, const char *name,
                  int ps5, const char *dst_dir, backup_stats_t *stats) {
  char image[PATH_MAX];
  const char *label = dst_dir;
  char why[160];
  uint8_t sealed[0x60];
  uint8_t key[0x20];
  const char *save = name;
  sv_result_t result = SV_FAILED;
  unsigned failed_before;
  struct stat ist, after;
  MountOpt mopt;
  int mounted = 0;
  int have_tmp = 0;
  int ret;
  int fd;

  g_game_abort = 0;
  snprintf(g_watch_title, sizeof g_watch_title, "%s", title);

  if(!strncmp(save, "sdimg_", 6)) {
    save += 6;
  }

  snprintf(image, sizeof image, "%s/%s", tdir, name);

  if(lstat(image, &ist) || !S_ISREG(ist.st_mode)) goto fail;

  /* the size of the whole game was already checked per title id */
  if(ist.st_size < 0x860) {
    logq("Failed to backup %s (not a save image)", label);
    stats->failed++;
    return SV_FAILED;
  }

  /* Use the image size as a conservative bound. */
  if(backup_free() < (uint64_t)ist.st_size + SPACE_MARGIN) {
    logq("Failed to backup %s (not enough space on M.2)", label);
    stats->failed++;
    return SV_FAILED;
  }

  /* Never stage/mount this title while it is running or suspended. */
  if(title_blocked(title, why, sizeof why, 1)) {
    g_game_abort = 1;
    snprintf(g_abort_why, sizeof g_abort_why, "%s", why);
    return SV_GAME;
  }

  /* sealed key: PS4 keeps it in a companion .bin file, PS5 inside the image */
  if(ps5) {
    if((fd = open(image, O_RDONLY)) < 0) {
      goto fail;
    }
    ret = pread(fd, sealed, sizeof sealed, 0x800);
    close(fd);
  } else {
    char bin[PATH_MAX];

    snprintf(bin, sizeof bin, "%s/%s.bin", tdir, save);
    if((fd = open(bin, O_RDONLY)) < 0) {
      goto fail;
    }
    ret = read(fd, sealed, sizeof sealed);
    close(fd);
  }
  if(ret != (int)sizeof sealed) {
    goto fail;
  }

  if(!enough_space((uint64_t)ist.st_size + SPACE_MARGIN)) {
    logq("Failed to backup %s (not enough free space)", label);
    stats->failed++;
    return SV_FAILED;
  }

  g_watch_game = 1;
  g_last_watch = now_seconds();

  /* work on a private copy; the original image is never mounted */
  mkdir_p(TMP_DIR);
  unlink(TMP_IMG);
  have_tmp = 1;
  g_progress_image = 1;
  progress_begin(ist.st_size);
  progress_stage(ist.st_size, 0, 0.5);
  ret = copy_plain(image, TMP_IMG);
  if(ret == -2) {
    result = SV_GAME;
    goto cleanup;
  }
  if(ret < 0) {
    goto fail_cleanup;
  }

  /* last check right before the mount */
  if(title_blocked(title, why, sizeof why, 1)) {
    g_game_abort = 1;
    snprintf(g_abort_why, sizeof g_abort_why, "%s", why);
    result = SV_GAME;
    goto cleanup;
  }

  if(stat(image, &after) || !source_same(&ist, &after)) {
    logq("Save image changed while staging: %s", label);
    goto fail_cleanup;
  }

  if(decrypt_key(sealed, key)) {
    goto fail_cleanup;
  }

  if(mkdir(PFS_ROOT, 0777) && errno != EEXIST) {
    goto fail_cleanup;
  }
  mkdir(MOUNT_POINT, 0777);

  memset(&mopt, 0, sizeof mopt);
  sceFsInitMountSaveDataOpt(&mopt);
  mopt.budgetid = "system";

  if(title_blocked(title, why, sizeof why, 1)) {
    g_game_abort = 1;
    snprintf(g_abort_why, sizeof g_abort_why, "%s", why);
    result = SV_GAME;
    goto cleanup;
  }
  const int mount_result = mount_save(&mopt, TMP_IMG, key);
  memset(key, 0, sizeof key);
  if(mount_result < 0) {
    const int error = errno;
    if(rmdir(MOUNT_POINT) && errno != ENOENT) {
      g_mount_stuck = 1;
      have_tmp = 0;
    }
    if(error == EBUSY && !g_mount_stuck) {
      result = SV_GAME;
      goto cleanup;
    }
    goto fail_cleanup;
  }
  mounted = 1;

  progress_stage(dir_size(MOUNT_POINT), 0.5, 0.5);
  failed_before = stats->failed;
  g_file_cap = 0;     /* the whole game was already judged against its limit */
  backup_tree(MOUNT_POINT, dst_dir, stats);
  g_file_cap = MAX_FILE_SZ;

  game_watch();
  if(title_blocked(title, why, sizeof why, 1)) g_game_abort = 1;
  if(g_game_abort) {
    result = SV_GAME;
  } else if(stat(image, &after) || !source_same(&ist, &after)) {
    logq("Save image changed during backup: %s", label);
  } else if(stats->failed == failed_before) {
    result = SV_OK;
  }
  goto cleanup;

fail_cleanup:
  result = SV_FAILED;

cleanup:
  /* the image must ALWAYS be unmounted again */
  if(mounted) {
    if(unmount_save()) {
      g_mount_stuck = 1;
      logq("Failed to unmount save image; PS4/PS5 saves backup disabled");
      notify_system_info("Save backup paused: cleanup failed.");
      g_watch_game = 0;
      progress_finish();
      g_progress_image = 0;
      stats->failed++;
      return SV_FAILED;
    }
    rmdir(MOUNT_POINT);
  }
  if(have_tmp) {
    unlink(TMP_IMG);
  }
  g_watch_game = 0;
  progress_finish();
  g_progress_image = 0;

  if(result == SV_FAILED) {
    logq("Failed to backup %s", label);
    stats->failed++;
  }
  return result;

fail:
  logq("Failed to backup %s", label);
  stats->failed++;
  return SV_FAILED;
}


typedef struct img_info {
  char     name[256];
  file_signature_t signature;
  int      needed;       /* changed since the last backup */
} img_info_t;


/**
 * Is this directory entry a save image we should back up?
 **/
static int
is_save_image(const char *n, int ps5) {
  size_t len = strlen(n);

  const char *slot = !strncmp(n, "sdimg_", 6) ? n + 6 : n;
  if(!*slot || slot[0] == '.' || len >= 200 || strpbrk(n, "/\\") ||
     (len >= 8 && (!strcmp(n + len - 8, ".unsaved") ||
                   !strcmp(n + len - 8, ".smp-new"))) ||
     (len >= 10 && !strcmp(n + len - 10, ".ps5up-tmp"))) {
    return 0;
  }
  if(len > 4 && !strcmp(n + len - 4, ".bin")) {
    return 0;                       /* PS4 sealed key */
  }
  if(!strncmp(n, "sdimg_sce_bu_", 13) || !strncmp(n, "sce_bu_", 7)) {
    return 0;                       /* system backup copies */
  }
  if(!ps5 && strncmp(n, "sdimg_", 6)) {
    return 0;                       /* PS4 images are always sdimg_* */
  }
  return 1;
}

static const char *
image_slot(const char *name) {
  return strncmp(name, "sdimg_", 6) ? name : name + 6;
}

static int
version_slot_count(const char *path) {
  DIR *dir = backup_opendir(path);
  if(!dir) return -1;
  int count = 0;
  struct dirent *e;
  while((e = readdir(dir))) {
    if(e->d_name[0] == '.') continue;
    struct stat st;
    if(!fstatat(dirfd(dir), e->d_name, &st, AT_SYMLINK_NOFOLLOW) && S_ISDIR(st.st_mode))
      count++;
  }
  closedir(dir);
  return count;
}

static int
write_version_marker(int staging) {
  static const char magic[] = SM_PS5SAVE_COMPLETE_MAGIC;
  int fd = openat(staging, SM_PS5SAVE_COMPLETE,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if(fd < 0) return -1;
  int rc = write(fd, magic, sizeof magic - 1) != sizeof magic - 1 || fsync(fd);
  if(close(fd)) rc = -1;
  return rc || sync_backup_directory(staging) ? -1 : 0;
}

static sv_result_t
save_game_version(const char *game, const char *previous, const char *title,
                  const char *tdir, const struct stat *before, int ps5,
                  const img_info_t *imgs, int count, backup_stats_t *stats) {
  if(mkdir_p(game)) return SV_FAILED;
  int parent = open_backup_dir(game);
  if(parent < 0) return SV_FAILED;
  if(remove_backup_tree(parent, VERSION_STAGING, 0) || mkdirat(parent, VERSION_STAGING, 0777)) {
    close(parent);
    return SV_FAILED;
  }

  backup_stats_t staged = {0};
  sv_result_t result = SV_OK;
  for(int i = 0; i < count && result == SV_OK && !interrupted(); i++) {
    const char *slot = image_slot(imgs[i].name);
    char dst[PATH_MAX];
    snprintf(dst, sizeof dst, "%s/" VERSION_STAGING "/%s", game, slot);
    if(imgs[i].needed) {
      result = backup_save_image(title, tdir, imgs[i].name, ps5, dst, &staged);
    } else {
      char src[PATH_MAX];
      snprintf(src, sizeof src, "%s/%s/%s", game, previous, slot);
      if(clone_version_tree(src, dst, &staged.bytes, 0)) result = SV_FAILED;
      staged.unchanged++;
    }
    if(result == SV_OK && stamp_write(dst, &imgs[i].signature)) result = SV_FAILED;
  }

  /* Ensure that every slot still matches the original scan, including slots
   * we reused from the previous version. A changed directory means an image
   * might have appeared or disappeared during the pass. */
  char why[160];
  struct stat after;
  if(result == SV_OK && (interrupted() || title_blocked(title, why, sizeof why, 1)))
    result = SV_GAME;
  if(result == SV_OK && (lstat(tdir, &after) || !source_same(before, &after)))
    result = SV_FAILED;
  for(int i = 0; result == SV_OK && i < count; i++) {
    char image[PATH_MAX];
    snprintf(image, sizeof image, "%s/%s", tdir, imgs[i].name);
    if(lstat(image, &after)) result = SV_FAILED;
    else {
      file_signature_t sig = file_signature(&after);
      if(memcmp(&sig, &imgs[i].signature, sizeof sig)) result = SV_FAILED;
    }
  }
  if(result == SV_OK) {
    unsigned long long version_time = (unsigned long long)wall_clock() * 1000000ULL;
    unsigned long long previous_time = previous[0] ? strtoull(previous + 1, NULL, 10) : 0;
    if(version_time <= previous_time) version_time = previous_time + 1;
    char version[SM_PS5SAVE_VERSION_SIZE];
    int length = snprintf(version, sizeof version, "v%016llu", version_time);
    int stage = openat(parent, VERSION_STAGING, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    struct stat exists;
    if(stage < 0 || length != sizeof version - 1 || write_version_marker(stage) ||
       !fstatat(parent, version, &exists, AT_SYMLINK_NOFOLLOW) || errno != ENOENT ||
       interrupted() || renameat(parent, VERSION_STAGING, parent, version)) {
      result = SV_FAILED;
    } else if(sync_backup_directory(parent)) {
      /* Keep an unconfirmed publication out of the restore catalog. */
      if(renameat(parent, version, parent, VERSION_STAGING))
        (void)unlinkat(stage, SM_PS5SAVE_COMPLETE, 0);
      result = SV_FAILED;
    } else {
      stats->copied += staged.copied + 1;
      stats->bytes += staged.bytes;
      stats->unchanged += staged.unchanged;
    }
    if(stage >= 0) close(stage);
  }
  if(result != SV_OK) (void)remove_backup_tree(parent, VERSION_STAGING, 0);
  close(parent);
  return result;
}

/* Scan one profile. Stage only games with changed images or a changed slot list. */
static void
scan_saves(const char *uid, int ps5, backup_stats_t *stats) {
  char base[PATH_MAX];
  img_info_t *imgs;
  struct dirent *td;
  DIR *bd;

  snprintf(base, sizeof base, "%s/%s/%s", HOME_ROOT, uid,
           ps5 ? "savedata_prospero" : "savedata");
  if(!(bd = opendir(base))) {
    if(errno != ENOENT) stats->failed++;
    return;
  }
  if(!(imgs = calloc(MAX_IMAGES, sizeof *imgs))) {
    stats->failed++;
    closedir(bd);
    return;
  }

  while(!interrupted() && (td = readdir(bd)) && !g_mount_stuck) {
    char tdir[PATH_MAX];
    const char *platform = ps5 ? "ps5" : "ps4";
    char game[64], previous[SM_PS5SAVE_VERSION_SIZE];
    char tlabel[64], last[96];
    char dst_dir[PATH_MAX];
    char key[PATH_MAX + 8];
    char a[32];
    char b[32];
    uint64_t total = 0;       /* all images of the game */
    uint64_t need_total = 0;  /* images that must be backed up now */
    uint64_t max_need = 0;
    uint64_t required;
    int n = 0;
    int needed = 0;
    int overflow = 0;
    struct dirent *ie;
    struct stat st, before;
    DIR *id;

    if(!title_valid(td->d_name)) {
      continue;
    }
    if(snprintf(tdir, sizeof tdir, "%s/%s", base, td->d_name) >= (int)sizeof tdir ||
       lstat(tdir, &before) || !S_ISDIR(before.st_mode)) {
      continue;
    }
    pending_title_t *queued = pending_find(uid, td->d_name, ps5);
    if(g_pending_only && (!queued || !queued->ready)) continue;
    if(!g_progress_planning && queued) {
      queued->ready = 0;
      queued->retry_at = now_seconds() + g_interval;
    }
    if(!(id = opendir(tdir))) {
      stats->failed++;
      continue;
    }
    snprintf(game, sizeof game, SM_PS5SAVE_VERSIONS "/%s/%s/%s", platform, uid, td->d_name);
    if(latest_version(game, previous)) {
      closedir(id);
      stats->failed++;
      continue;
    }
    snprintf(last, sizeof last, "%s/%s", game, previous);

    /* pass 1: size up the whole game without mounting anything */
    bool scan_error = false;
    while(!interrupted()) {
      errno = 0;
      ie = readdir(id);
      if(!ie) {
        scan_error = errno != 0;
        break;
      }
      char path[PATH_MAX];

      if(!is_save_image(ie->d_name, ps5)) {
        continue;
      }
      if(snprintf(path, sizeof path, "%s/%s", tdir, ie->d_name) >= (int)sizeof path ||
         lstat(path, &st)) {
        scan_error = true;
        break;
      }
      if(!S_ISREG(st.st_mode)) continue;
      if(n >= MAX_IMAGES) {
        overflow = 1;
        break;
      }

      snprintf(dst_dir, sizeof dst_dir, "%s/%s", last, image_slot(ie->d_name));

      snprintf(imgs[n].name, sizeof imgs[n].name, "%s", ie->d_name);
      imgs[n].signature = file_signature(&st);
      imgs[n].needed = !previous[0] || !stamp_current(dst_dir, &st);
      total += st.st_size;
      if(imgs[n].needed) {
        needed++;
        need_total += st.st_size;
        /* Image size bounds decrypted data without walking the backup tree. */
        if((uint64_t)st.st_size > max_need) {
          max_need = st.st_size;
        }
      }
      n++;
    }
    closedir(id);
    if(scan_error) {
      stats->failed++;
      continue;
    }
    if(n == 0 || interrupted()) {
      continue;
    }

    if(g_progress_planning) {
      if(!overflow && total <= g_max_game) progress_plan(needed);
      continue;
    }

    snprintf(tlabel, sizeof tlabel, "%s/%s/%s", platform, uid, td->d_name);

    /* 1. per-game size limit: the whole game or nothing */
    if(overflow || total > g_max_game) {
      snprintf(key, sizeof key, "size:%s", tlabel);
      if(!seen_before(key)) {
        format_size(total, a, sizeof a);
        format_size(g_max_game, b, sizeof b);
        logq("Abnormal size of %s; skipping backup (%s%s, limit %s)", tlabel,
             overflow ? ">" : "", a, b);
      }
      stats->failed++;
      continue;
    }

    if(!needed && version_slot_count(last) == n) {
      pending_remove(uid, td->d_name, ps5);
      stats->unchanged += n;
      continue;
    }

    char why[160];
    if(title_blocked(td->d_name, why, sizeof why, 1)) {
      pending_defer(uid, td->d_name, ps5);
      logq("Deferred %s: %s", td->d_name, why);
      continue;
    }

    /* 2. the largest image is copied to internal storage first */
    if(max_need && !enough_space(max_need + SPACE_MARGIN)) {
      snprintf(key, sizeof key, "tmp:%s", tlabel);
      if(!seen_before(key)) {
        format_size(max_need + SPACE_MARGIN, a, sizeof a);
        format_size(data_free(), b, sizeof b);
        logq("Not enough internal storage for %s (need %s, free %s); "
             "skipping backup", tlabel, a, b);
      }
      stats->failed++;
      continue;
    }

    /* 3. the M.2 must be able to hold everything that is going to be
     * written (image sizes are an upper bound of the decrypted content) */
    required = need_total + SPACE_MARGIN;
    uint64_t free_bytes = backup_free();
    if(free_bytes < required) {
      snprintf(key, sizeof key, "m2:%s", tlabel);
      if(!seen_before(key)) {
        format_size(required, a, sizeof a);
        format_size(free_bytes, b, sizeof b);
        logq("Not enough space on M.2 for %s (need ~%s, free %s); "
             "skipping backup", tlabel, a, b);
      }
      stats->failed++;
      continue;
    }

    sv_result_t result = save_game_version(game, previous, td->d_name, tdir,
                                          &before, ps5, imgs, n, stats);
    g_game_abort = 0;
    if(result == SV_GAME) pending_defer(uid, td->d_name, ps5);
    if(result == SV_FAILED) {
      logq("Failed to commit save version for %s", tlabel);
      stats->failed++;
    }
    if(result == SV_OK) {
      pending_remove(uid, td->d_name, ps5);
      version_list_t dates = {0};
      if(legacy_dates(&dates) || prune_game_versions(platform, uid, td->d_name, &dates)) {
        logq("Failed to prune old backups for %s", tlabel);
        stats->failed++;
      }
      free(dates.names);
    }
  }

  free(imgs);
  closedir(bd);
}


/**
 * Back up decrypted PS4/PS5 saves for every user, as enabled in backup.conf.
 **/
static void
backup_saves(backup_stats_t *stats) {
  struct dirent *ud;
  DIR *hd;

  if(!g_progress_planning && (g_need_cleanup || g_mount_stuck)) {
    cleanup_stale();
    g_need_cleanup = 0;
  }
  if(g_mount_stuck) {
    logq("A previous save mount could not be removed; saves backup disabled");
    stats->failed++;
    return;
  }

  if(!interrupted() && (hd = opendir(HOME_ROOT))) {
    while(!interrupted() && (ud = readdir(hd)) && !g_mount_stuck) {
      if(!is_hex_name(ud->d_name)) {
        continue;
      }
      if(g_ps4saves) {
        scan_saves(ud->d_name, 0, stats);
      }
      if(g_ps5saves && !g_mount_stuck) {
        scan_saves(ud->d_name, 1, stats);
      }
    }
    closedir(hd);
  }

  g_watch_game = 0;
}


/* ------------------------------------------------------------------------
 * backup.conf handling and the main loop
 * ---------------------------------------------------------------------- */

/* Match a setting name, allowing spaces before and after '='. */
static const char *
config_value(const char *line, const char *key, const char *legacy) {
  const char *names[2] = {key, legacy};
  for(int i = 0; i < 2; i++) {
    size_t n = strlen(names[i]);
    if(strncmp(line, names[i], n)) {
      continue;
    }
    const char *p = line + n;
    while(*p == ' ' || *p == '\t') p++;
    if(*p++ != '=') continue;
    while(*p == ' ' || *p == '\t') p++;
    return p;
  }
  return NULL;
}

static int
config_number(const char *value, long min, long max, long *out) {
  char *end;
  errno = 0;
  long v = strtol(value, &end, 10);
  if(errno || end == value || *end) {
    logq("Invalid numeric setting: %s", value);
    return 0;
  }
  if(v < min || v > max) {
    logq("Numeric setting out of range: %s (expected %ld..%ld)",
         value, min, max);
    return 0;
  }
  *out = v;
  return 1;
}

/* Compare complete path components. Both paths must be canonical. */
static int
path_contains(const char *parent, const char *path) {
  size_t n = strlen(parent);
  return !strcmp(parent, "/") ||
         (!strncmp(parent, path, n) && (path[n] == '/' || path[n] == '\0'));
}

/**
 * Handle a single line from backup.conf.
 **/
static void
backup_entry(char *line, backup_stats_t *stats) {
  char dst[PATH_MAX];
  char src[PATH_MAX];
  struct stat st;
  size_t len;

  /* trim whitespace and CR/LF */
  while(*line == ' ' || *line == '\t') {
    line++;
  }
  len = strlen(line);
  while(len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                    line[len-1] == ' '  || line[len-1] == '\t')) {
    line[--len] = 0;
  }

  if(len == 0 || line[0] == '#') {
    return;
  }

  /* Keep legacy key aliases for existing backup.conf files. All MB values
   * now mean decimal megabytes, including the legacy max_game_mb key. */
  const char *value;
  if((value = config_value(line, "backup_interval_seconds", "interval"))) {
    long v;
    if(!config_number(value, MIN_INTERVAL, MAX_INTERVAL, &v)) {
      return;
    }
    g_interval = v;
    return;
  }
  if((value = config_value(line, "max_title_size_mb", "max_game_mb"))) {
    long v;
    if(!config_number(value, MIN_GAME_MB, MAX_GAME_MB, &v)) {
      return;
    }
    g_max_game = (uint64_t)v * BYTES_PER_MB;
    return;
  }
  if((value = config_value(line, "backup_trophies", "trophies"))) {
    parse_bool(value, &g_trophies);
    return;
  }
  if((value = config_value(line, "backup_ps4_saves", "ps4saves"))) {
    parse_bool(value, &g_ps4saves);
    return;
  }
  if((value = config_value(line, "backup_ps5_saves", "ps5saves"))) {
    parse_bool(value, &g_ps5saves);
    return;
  }

  if(g_pending_only || !stats) return;

  /* only absolute paths are valid entries */
  if(line[0] != '/') {
    return;
  }

  /* strip the trailing star wildcard (and the slash before it) */
  if(line[len-1] == '*') {
    line[--len] = 0;
    while(len > 1 && line[len-1] == '/') {
      line[--len] = 0;
    }
  }

  if(!realpath(line, src) || stat(src, &st)) {
    logq("Failed to backup %s", line);
    stats->failed++;
    return;
  }

  /* Exclude custom paths that would recursively copy the destination. */
  const char backup_dir[] = M2_MOUNT "/" M2_BACKUP_DIR;
  if(path_contains(backup_dir, src) || path_contains(src, backup_dir)) {
    logq("Skipping custom path that overlaps the backup directory: %s", src);
    return;
  }

  if(snprintf(dst, sizeof dst, "%s%s", BACKUP_ROOT, src) >= (int)sizeof dst) {
    return;
  }

  if(S_ISDIR(st.st_mode)) {
    backup_tree(src, dst, stats);
  } else if(S_ISREG(st.st_mode)) {
    backup_file(src, dst, &st, stats);
  }
}


static void
copy_trophy_dir(const char *source, backup_stats_t *stats) {
  struct stat st;
  if(lstat(source, &st)) {
    if(errno != ENOENT) stats->failed++;
    return;
  }
  if(!S_ISDIR(st.st_mode)) return;
  char dst[PATH_MAX];
  if(snprintf(dst, sizeof dst, BACKUP_ROOT "%s", source) >= (int)sizeof dst) {
    stats->failed++;
    return;
  }
  backup_tree(source, dst, stats);
}

static void
backup_trophies(backup_stats_t *stats) {
  const char *names[] = {"trophy", "trophy2"};
  g_file_cap = 0;
  for(size_t i = 0; i < 2 && !interrupted(); i++) {
    char path[PATH_MAX];
    snprintf(path, sizeof path, USER_ROOT "/%s", names[i]);
    copy_trophy_dir(path, stats);
  }
  DIR *home = opendir(HOME_ROOT);
  if(home) {
    struct dirent *profile;
    while(!interrupted() && (profile = readdir(home))) {
      if(!is_hex_name(profile->d_name)) continue;
      struct stat st;
      if(fstatat(dirfd(home), profile->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
         !S_ISDIR(st.st_mode)) continue;
      for(size_t i = 0; i < 2; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof path, HOME_ROOT "/%s/%s", profile->d_name, names[i]);
        copy_trophy_dir(path, stats);
      }
    }
    closedir(home);
  } else if(errno != ENOENT) stats->failed++;
  g_file_cap = MAX_FILE_SZ;
}

static int
read_backup_config(FILE *file, backup_stats_t *stats) {
  char line[PATH_MAX + 16];
  g_interval = DEF_INTERVAL;
  g_max_game = DEF_GAME_MB * BYTES_PER_MB;
  g_ps4saves = g_ps5saves = 0;
  g_trophies = 1;
  while(!interrupted() && fgets(line, sizeof line, file))
    backup_entry(line, stats);
  return ferror(file) ? -1 : 0;
}

static void
load_last_copy(void) {
  FILE *file = backup_fopen(LAST_COPY_PATH, "r");
  long long when = 0;
  int ok = 0;
  if(file) {
    struct stat st;
    if(fstat(fileno(file), &st) || !S_ISREG(st.st_mode) ||
       fscanf(file, "SMP1 %lld %d", &when, &ok) != 2 ||
       when <= 0 || (ok != 0 && ok != 1)) when = 0;
    fclose(file);
  }
  pthread_mutex_lock(&g_status_lock);
  g_backup_status.last_copy_at = when;
  g_backup_status.last_copy_ok = when > 0 && ok != 0;
  pthread_mutex_unlock(&g_status_lock);
}

static int
record_last_copy(bool ok) {
  long long when = wall_clock();
  int fd = -1;
  if(!unlinkat(g_backup_directory, LAST_COPY_PATH ".part", 0) || errno == ENOENT)
    fd = openat(g_backup_directory, LAST_COPY_PATH ".part",
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  FILE *file = fd >= 0 ? fdopen(fd, "w") : NULL;
  int rc = -1;
  if(file) {
    bool written = fprintf(file, "SMP1 %lld %d\n", when, ok) > 0 &&
        !fflush(file) && !fsync(fileno(file));
    if(fclose(file)) written = false;
    if(written)
      rc = renameat(g_backup_directory, LAST_COPY_PATH ".part",
                    g_backup_directory, LAST_COPY_PATH);
    if(!rc) rc = sync_backup_directory(g_backup_directory);
  } else if(fd >= 0) close(fd);
  if(rc) (void)unlinkat(g_backup_directory, LAST_COPY_PATH ".part", 0);
  pthread_mutex_lock(&g_status_lock);
  g_backup_status.last_copy_at = when;
  g_backup_status.last_copy_ok = ok && !rc;
  pthread_mutex_unlock(&g_status_lock);
  return rc;
}

/** Run one backup pass against the open destination directory. */
static int
run_cycle(FILE *f, int pending_only) {
  backup_stats_t stats = {0};
  char size[32];
  double start = now_seconds();

  progress_reset();
  index_load();
  g_pending_only = pending_only;
  g_cycle_deferred = 0;
  g_backup_busy = 0;
  if(!g_start_logged) {
    logq("Backup utility started");
    g_start_logged = 1;
  }
  g_game_abort = 0;
  g_watch_game = 0;

  g_progress_planning = 1;
  int rc = read_backup_config(f, &stats);
  if(g_ps4saves || g_ps5saves) backup_saves(&stats);
  if(!g_pending_only && g_trophies) backup_trophies(&stats);
  g_progress_planning = 0;

  memset(&stats, 0, sizeof stats);
  if(rc || fseek(f, 0, SEEK_SET) || read_backup_config(f, &stats)) {
    stats.failed++;
  } else {
    pending_disable();
    if(g_pending_only) {
      for(pending_title_t *p = pending_titles; p; p = p->next)
        if(p->ready) p->retry_at = now_seconds() + g_interval;
    }
    if(g_ps4saves || g_ps5saves) backup_saves(&stats);
    if(!g_pending_only && g_trophies) backup_trophies(&stats);
  }

  index_save();
  progress_stop();
  if((stats.copied || (stats.failed && !interrupted())) &&
     record_last_copy(!stats.failed && !interrupted())) {
    logq("Cannot save last backup result on M.2");
    stats.failed++;
  }

  if(stats.failed) {
    /* announce only on the first failed cycle until recovery */
    if(!g_last_failed) {
      logq("Backup incomplete (%u errors, %u copy units written)",
           stats.failed, stats.copied);
      notify_system_info("Backup incomplete (%u failed).", stats.failed);
    }
    g_last_failed = 1;
  } else if(stats.copied || (g_last_failed && !g_cycle_deferred)) {
    format_size(stats.bytes, size, sizeof size);
    logq("Successful backup (%s) done in %.1f seconds.", size,
         now_seconds() - start);
    g_last_failed = 0;
  } else if(g_cycle_deferred) {
    logq("Backup pass finished; protected titles queued (%u files unchanged)", stats.unchanged);
  } else {
    logq("Backup up to date (%u files unchanged)", stats.unchanged);
  }

  return stats.failed ? 1 : 0;
}


/* An ordinary directory at the mount path is not the SSD. */
static int
on_mounted_ssd(int fd) {
#ifndef BACKUP_HOST_TEST
  struct statfs fs;
  return fstatfs(fd, &fs) == 0 &&
         !strncmp(fs.f_mntonname, M2_MOUNT, sizeof fs.f_mntonname) &&
         !(fs.f_flags & MNT_RDONLY);
#else
  struct statvfs fs;
  return fstatvfs(fd, &fs) == 0 && !(fs.f_flag & ST_RDONLY);
#endif
}

static bool
same_backup_volume(int fd) {
#ifndef BACKUP_HOST_TEST
  struct statfs root, child;
  return fstatfs(g_backup_directory, &root) == 0 && fstatfs(fd, &child) == 0 &&
      memcmp(&root.f_fsid, &child.f_fsid, sizeof root.f_fsid) == 0;
#else
  struct stat root, child;
  return fstat(g_backup_directory, &root) == 0 && fstat(fd, &child) == 0 &&
      root.st_dev == child.st_dev;
#endif
}

static int
backup_subdir_available(const char *path) {
  struct stat st;
  if(fstatat(g_backup_directory, path, &st, AT_SYMLINK_NOFOLLOW)) return errno == ENOENT;
  if(!S_ISDIR(st.st_mode)) return 0;
  int fd = openat(g_backup_directory, path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if(fd < 0) return 0;
  bool on_ssd = same_backup_volume(fd);
  close(fd);
  return on_ssd;
}

/* Keep the standalone utility's loopback lease. Never contact the listener:
 * a connection is the standalone utility's command to stop. */
static int
reserve_ps5save_port(void) {
  struct sockaddr_in address = {
    .sin_family = AF_INET,
    .sin_port = htons(LOCK_PORT),
    .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) }
  };
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) return -1;
  int one = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  if(bind(fd, (struct sockaddr *)&address, sizeof address) == 0 &&
     listen(fd, 1) == 0) return fd;
  const int error = errno;
  close(fd);
  errno = error;
  return -1;
}

static int
open_backup_root(void) {
  int volume = open(M2_MOUNT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if(volume < 0 || !on_mounted_ssd(volume)) {
    if(volume >= 0) close(volume);
    errno = ENODEV;
    return -1;
  }
  int fd = openat(volume, M2_BACKUP_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  int error = errno;
  close(volume);
  if(fd >= 0 && !on_mounted_ssd(fd)) {
    close(fd);
    fd = -1;
    error = ENODEV;
  }
  errno = error;
  return fd;
}

static FILE *
open_backup_config(int root, struct stat *st) {
  int fd = openat(root, CONF_PATH, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  if(fd < 0) return NULL;
  FILE *file = NULL;
  if(!fstat(fd, st)) {
    if(S_ISREG(st->st_mode)) file = fdopen(fd, "r");
    else errno = EINVAL;
  }
  if(!file) {
    int error = errno;
    close(fd);
    errno = error;
  }
  return file;
}

static const char *
run_m2_backup(bool pending_only, bool maintenance_only, bool *prepared, bool *configured) {
  g_backup_directory = open_backup_root();
  if(g_backup_directory < 0) {
    *prepared = *configured = false;
    return errno == ENODEV ? "no_m2" : "no_config";
  }
  const char *outcome = "no_config";
  if(backup_subdir_available(BACKUP_ROOT) &&
     backup_subdir_available(SM_PS5SAVE_VERSIONS)) {
    bool cleanup_error = false;
    if(!*prepared) {
      load_last_copy();
      cleanup_error = prune_all_versions() != 0;
      *prepared = !cleanup_error && !interrupted();
      if(cleanup_error && !interrupted()) logq("Old save versions could not be pruned");
    }
    struct stat st;
    FILE *file = open_backup_config(g_backup_directory, &st);
    *configured = file != NULL;
    if(file) {
      int result = maintenance_only ? read_backup_config(file, NULL)
                                    : run_cycle(file, pending_only);
      if(fclose(file)) result = -1;
      outcome = interrupted() ? "waiting" : result || cleanup_error ? "backup_error" : "ready";
    }
  } else {
    *configured = false;
    outcome = "backup_error";
  }
  close(g_backup_directory);
  g_backup_directory = -1;
  return outcome;
}

static void
wait_for_backup(double seconds) {
  if(seconds <= 0) return;
  struct timespec until;
  if(clock_gettime(CLOCK_REALTIME, &until) != 0) return;
  long nanoseconds = (long)(seconds * 1e9);
  until.tv_sec += nanoseconds / 1000000000L;
  until.tv_nsec += nanoseconds % 1000000000L;
  if(until.tv_nsec >= 1000000000L) {
    until.tv_sec++;
    until.tv_nsec -= 1000000000L;
  }
  (void)pthread_cond_timedwait(&g_backup_wake, &g_status_lock, &until);
}

static void *
backup_worker(void *unused) {
  (void)unused;
  double due = now_seconds();
  bool sleeping = false;
  bool prepared = false;
  bool configured = false;
  unsigned schedule_revision = 0;
  pthread_mutex_lock(&g_status_lock);
  while(!atomic_load(&g_stopping)) {
    if(runtime_sleep_mode_active() ||
       (!g_backup_status.enabled && !g_manual_requested && prepared && configured)) {
      sleeping = true;
      wait_for_backup(SLICE_SEC);
      continue;
    }
    const double started = now_seconds();
    if(sleeping) {
      due = started;
      sleeping = false;
    }
    if(schedule_revision != g_schedule_revision) {
      schedule_revision = g_schedule_revision;
      due = g_schedule_changed + g_backup_status.interval_seconds;
    }
    const double remaining = due - started;
    const bool manual = g_manual_requested;
    const bool scheduled = g_backup_status.enabled;
    pthread_mutex_unlock(&g_status_lock);
    const bool pending = !manual && remaining > 0 && scheduled && pending_ready();
    pthread_mutex_lock(&g_status_lock);
    if(atomic_load(&g_stopping)) break;
    if(runtime_sleep_mode_active() || scheduled != g_backup_status.enabled ||
       manual != g_manual_requested || schedule_revision != g_schedule_revision)
      continue;
    if(!manual && remaining > 0 && !pending) {
      const double slice = pending_titles ? CLOSE_POLL_SEC : SLICE_SEC;
      wait_for_backup(remaining < slice ? remaining : slice);
      continue;
    }
    if(pthread_mutex_trylock(&g_save_io_lock) != 0) {
      wait_for_backup(1);
      continue;
    }
    g_manual_requested = false;
    g_backup_status.busy = true;
    g_backup_status.state = "running";
    pthread_mutex_unlock(&g_status_lock);

    int lease = reserve_ps5save_port();
    const char *outcome = lease >= 0
        ? run_m2_backup(pending, !scheduled && !manual, &prepared, &configured) :
        errno == EADDRINUSE ? "standalone_running" : "backup_error";
    if(lease >= 0) close(lease);
    pthread_mutex_unlock(&g_save_io_lock);

    pthread_mutex_lock(&g_status_lock);
    g_backup_status.busy = false;
    g_backup_status.state = outcome;
    g_backup_status.configured = configured;
    if(configured) {
      if(schedule_revision == g_schedule_revision)
        g_backup_status.interval_seconds = g_interval;
      g_backup_status.ps4 = g_ps4saves != 0;
      g_backup_status.ps5 = g_ps5saves != 0;
      g_backup_status.trophies = g_trophies != 0;
    }
    if(!configured || strcmp(outcome, "standalone_running") == 0 ||
       strcmp(outcome, "waiting") == 0) {
      pending_retry_after = started + SLICE_SEC * 3;
      due = pending_retry_after;
    } else {
      if(!pending) {
        long interval = g_backup_status.interval_seconds;
        due = started + interval;
        double now = now_seconds();
        if(due <= now) due = now + interval;
      }
      pending_retry_after = 0;
    }
  }
  pthread_mutex_unlock(&g_status_lock);
  return NULL;
}

bool
sm_ps5save_backup_start(void) {
  struct stat paused;
  g_backup_status = (sm_ps5save_backup_status_t){
    .enabled = lstat(BACKUP_PAUSE_FILE, &paused) != 0,
    .state = "waiting", .interval_seconds = DEF_INTERVAL
  };
  g_manual_requested = false;
  g_schedule_revision = 0;
  g_schedule_changed = 0;
  g_last_failed = 0;
  atomic_store(&g_stopping, false);
  g_buf = malloc(COPY_BUF_SZ);
  if(!g_buf) {
    g_backup_status.state = "unavailable";
    return false;
  }
  pthread_attr_t attr;
  int result = pthread_attr_init(&attr);
  if(result == 0) {
    result = pthread_attr_setstacksize(&attr, 1024u * 1024u);
    if(result == 0) result = pthread_create(&g_backup_thread, &attr, backup_worker, NULL);
    pthread_attr_destroy(&attr);
  }
  g_worker_started = result == 0;
  if(!g_worker_started) {
    g_backup_status.state = "unavailable";
    free(g_buf);
    g_buf = NULL;
  }
  return g_worker_started;
}

void
sm_ps5save_backup_stop(void) {
  if(!g_worker_started) return;
  atomic_store(&g_stopping, true);
  pthread_mutex_lock(&g_status_lock);
  pthread_cond_signal(&g_backup_wake);
  pthread_mutex_unlock(&g_status_lock);
  pthread_join(g_backup_thread, NULL);
  g_worker_started = false;
  index_clear();
  while(pending_titles) {
    pending_title_t *next = pending_titles->next;
    free(pending_titles);
    pending_titles = next;
  }
  for(int i = 0; i < g_nseen; i++) free(g_seen[i]);
  g_nseen = 0;
  free(g_buf);
  g_buf = NULL;
}

sm_ps5save_backup_status_t
sm_ps5save_backup_status(void) {
  pthread_mutex_lock(&g_status_lock);
  sm_ps5save_backup_status_t result = g_backup_status;
  pthread_mutex_unlock(&g_status_lock);
  return result;
}

int
sm_ps5save_backup_request(void) {
  if(!g_worker_started || atomic_load(&g_stopping)) return ENODEV;
  if(runtime_sleep_mode_active()) return EBUSY;
  pthread_mutex_lock(&g_status_lock);
  if(!g_backup_status.busy) {
    g_manual_requested = true;
    g_backup_status.state = "queued";
    pthread_cond_signal(&g_backup_wake);
  }
  pthread_mutex_unlock(&g_status_lock);
  return 0;
}

int
sm_ps5save_backup_set_enabled(bool enabled) {
  if(!g_worker_started || atomic_load(&g_stopping)) return ENODEV;
  pthread_mutex_lock(&g_status_lock);
  int result = 0;
  if(enabled) {
    if(unlink(BACKUP_PAUSE_FILE) != 0 && errno != ENOENT) result = errno;
  } else {
    int fd = open(BACKUP_PAUSE_FILE, O_WRONLY | O_CREAT | O_NOFOLLOW, 0600);
    if(fd < 0) result = errno;
    else close(fd);
  }
  if(!result) {
    g_backup_status.enabled = enabled;
    if(enabled && !g_backup_status.busy) {
      g_manual_requested = true;
      g_backup_status.state = "queued";
    }
    pthread_cond_signal(&g_backup_wake);
  }
  pthread_mutex_unlock(&g_status_lock);
  return result;
}

/* Rewrite only the interval, using the same file as the pre-existing backup
 * configuration. An in-flight cycle keeps its already-open config file. */
static int
save_backup_interval(int root, long seconds) {
  const char temp[] = ".smp-config.part";
  struct stat st;
  FILE *input = open_backup_config(root, &st);
  if(!input) return errno;
  if(unlinkat(root, temp, 0) && errno != ENOENT) {
    int error = errno;
    fclose(input);
    return error;
  }
  int fd = openat(root, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                  st.st_mode & 0777);
  FILE *output = fd >= 0 ? fdopen(fd, "w") : NULL;
  if(!output) {
    int error = errno;
    if(fd >= 0) close(fd);
    fclose(input);
    return error;
  }
  char line[PATH_MAX + 16];
  int error = 0;
  bool newline = true;
  while(fgets(line, sizeof line, input)) {
    size_t n = strlen(line);
    bool end_of_line = n && line[n - 1] == '\n';
    if(!end_of_line && !feof(input)) {
      error = EINVAL;
      break;
    }
    const char *setting = line + strspn(line, " \t");
    if(config_value(setting, "backup_interval_seconds", "interval")) continue;
    if(fwrite(line, 1, n, output) != n) {
      error = errno ? errno : EIO;
      break;
    }
    newline = end_of_line;
  }
  if(!error && !feof(input)) error = errno ? errno : EIO;
  if(!error && ((!newline && fputc('\n', output) == EOF) ||
       fprintf(output, "backup_interval_seconds=%ld\n", seconds) < 0 ||
       fflush(output) || fsync(fileno(output)))) error = errno ? errno : EIO;
  fclose(input);
  if(fclose(output) && !error) error = errno ? errno : EIO;
  if(!error && renameat(root, temp, root, CONF_PATH)) error = errno;
  if(error) (void)unlinkat(root, temp, 0);
  if(!error) (void)sync_backup_directory(root);
  return error;
}

int
sm_ps5save_backup_set_interval(long minutes) {
  if(minutes < 1 || minutes > SM_PS5SAVE_MAX_INTERVAL_MINUTES) return EINVAL;
  if(!g_worker_started || atomic_load(&g_stopping)) return ENODEV;
  if(runtime_sleep_mode_active()) return EBUSY;
  pthread_mutex_lock(&g_status_lock);
  int root = open_backup_root();
  int error = root >= 0 ? save_backup_interval(root, minutes * 60L) : errno;
  if(root >= 0) close(root);
  if(!error) {
    g_backup_status.interval_seconds = minutes * 60L;
    g_schedule_changed = now_seconds();
    g_schedule_revision++;
    pthread_cond_signal(&g_backup_wake);
  }
  pthread_mutex_unlock(&g_status_lock);
  return error;
}

bool
sm_ps5save_try_begin_restore(void) {
  if(pthread_mutex_trylock(&g_save_io_lock) != 0) return false;
  g_restore_port = reserve_ps5save_port();
  if(g_restore_port >= 0) return true;
  pthread_mutex_unlock(&g_save_io_lock);
  return false;
}

void
sm_ps5save_end_restore(void) {
  close(g_restore_port);
  g_restore_port = -1;
  pthread_mutex_unlock(&g_save_io_lock);
}
