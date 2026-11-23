/* The worker holds the backup/restore lock while publishing or pruning. */
#define LEGACY_DAILY_ROOT "backup_daily"
#define VERSION_STAGING ".incomplete"
#define VERSIONS_TO_KEEP 3u

typedef struct {
  char (*names)[SM_PS5SAVE_VERSION_SIZE];
  size_t count;
} version_list_t;

static int
version_newest_first(const void *a, const void *b) {
  return strcmp(b, a);
}

static int
list_versions(int fd, int (*valid)(const char *), version_list_t *list) {
  int dup_fd = openat(fd, ".", O_RDONLY | O_DIRECTORY);
  if(dup_fd < 0) return -1;
  DIR *dir = fdopendir(dup_fd);
  if(!dir) {
    close(dup_fd);
    return -1;
  }
  int error = 0;
  size_t capacity = 0;
  while(!interrupted()) {
    errno = 0;
    struct dirent *entry = readdir(dir);
    if(!entry) {
      error = errno;
      break;
    }
    if(!valid(entry->d_name)) continue;
    if(list->count == capacity) {
      size_t next = capacity ? 2 * capacity : 8;
      void *items = realloc(list->names, next * sizeof *list->names);
      if(!items) {
        error = ENOMEM;
        break;
      }
      list->names = items;
      capacity = next;
    }
    strcpy(list->names[list->count++], entry->d_name);
  }
  closedir(dir);
  if(list->count > 1)
    qsort(list->names, list->count, sizeof *list->names, version_newest_first);
  return error || interrupted() ? -1 : 0;
}

static int
open_backup_dir(const char *path) {
  int fd = sm_ps5save_open_dir(g_backup_directory, path);
  if(fd >= 0 && !same_backup_volume(fd)) {
    int error = errno;
    close(fd);
    errno = error;
    return -1;
  }
  return fd;
}

/* Descend by descriptor. Neither symlinks nor nested mounts are followed. */
static int
remove_backup_tree(int parent, const char *name, unsigned depth) {
  struct stat st;
  if(depth > 32 || interrupted()) return -1;
  if(fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW)) return errno == ENOENT ? 0 : -1;
  if(!S_ISDIR(st.st_mode)) return unlinkat(parent, name, 0);
  int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if(fd < 0) return -1;
  DIR *dir = same_backup_volume(fd) ? fdopendir(fd) : NULL;
  if(!dir) {
    close(fd);
    return -1;
  }
  int rc = 0;
  while(!rc) {
    errno = 0;
    struct dirent *e = readdir(dir);
    if(!e) {
      rc = errno ? -1 : 0;
      break;
    }
    if(strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
      rc = remove_backup_tree(fd, e->d_name, depth + 1);
  }
  closedir(dir);
  return rc ? rc : unlinkat(parent, name, AT_REMOVEDIR);
}

static bool
completed_at(int parent, const char *name) {
  int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if(fd < 0) return false;
  bool complete = same_backup_volume(fd) && sm_ps5save_complete_version(fd);
  close(fd);
  return complete;
}

static int
latest_version(const char *game, char *version) {
  version[0] = 0;
  int fd = open_backup_dir(game);
  if(fd < 0) return errno == ENOENT ? 0 : -1;
  version_list_t list = {0};
  int rc = list_versions(fd, sm_ps5save_version_name, &list);
  for(size_t i = 0; !rc && i < list.count; i++) {
    if(completed_at(fd, list.names[i])) {
      strcpy(version, list.names[i]);
      break;
    }
  }
  free(list.names);
  close(fd);
  return rc;
}

/* Reuse unchanged slots from committed versions. A filesystem that cannot
 * hard-link files simply gets independent copies. Completed files are never
 * rewritten in place. */
static int
clone_version_tree(const char *src, const char *dst, uint64_t *bytes, unsigned depth) {
  if(depth > 31 || mkdirat(g_backup_directory, dst, 0777)) return -1;
  DIR *dir = backup_opendir(src);
  if(!dir) return -1;
  int rc = 0;
  while(!rc && !interrupted()) {
    errno = 0;
    struct dirent *e = readdir(dir);
    if(!e) {
      rc = errno ? -1 : 0;
      break;
    }
    const char *name = e->d_name;
    if(!strcmp(name, ".") || !strcmp(name, "..") || !strcmp(name, ".image_stamp"))
      continue;
    struct stat st;
    char from[PATH_MAX], to[PATH_MAX];
    if(snprintf(from, sizeof from, "%s/%s", src, name) >= (int)sizeof from ||
       snprintf(to, sizeof to, "%s/%s", dst, name) >= (int)sizeof to ||
       fstatat(dirfd(dir), name, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = -1;
    } else if(S_ISDIR(st.st_mode)) {
      rc = clone_version_tree(from, to, bytes, depth + 1);
    } else if(S_ISREG(st.st_mode)) {
      if(linkat(g_backup_directory, from, g_backup_directory, to, 0)) {
        rc = copy_version_file(from, to, &st);
        if(!rc) *bytes += st.st_size;
      }
    } else rc = -1;
  }
  closedir(dir);
  return rc || interrupted() ? -1 : sync_backup_path(dst);
}

static bool
legacy_slot_data(int slot, unsigned depth) {
  if(depth > 31 || interrupted()) return false;
  int fd = openat(slot, ".", O_RDONLY | O_DIRECTORY);
  if(fd < 0) return false;
  DIR *dir = fdopendir(fd);
  if(!dir) {
    close(fd);
    return false;
  }
  bool found = false;
  struct dirent *e;
  while(!found && (e = readdir(dir))) {
    if(e->d_name[0] == '.' || (!depth && !strcmp(e->d_name, "sce_sys"))) continue;
    size_t n = strlen(e->d_name);
    if(n >= 5 && !strcmp(e->d_name + n - 5, ".part")) continue;
    struct stat st;
    if(fstatat(slot, e->d_name, &st, AT_SYMLINK_NOFOLLOW)) continue;
    if(S_ISREG(st.st_mode)) found = true;
    if(S_ISDIR(st.st_mode)) {
      int sub = openat(slot, e->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
      if(sub < 0) continue;
      found = same_backup_volume(sub) && legacy_slot_data(sub, depth + 1);
      close(sub);
    }
  }
  closedir(dir);
  return found;
}

static bool
legacy_game_usable(int game, bool latest) {
  if(!same_backup_volume(game)) return false;
  int fd = openat(game, ".", O_RDONLY | O_DIRECTORY);
  if(fd < 0) return false;
  DIR *dir = fdopendir(fd);
  if(!dir) {
    close(fd);
    return false;
  }
  bool found = false;
  struct dirent *e;
  while(!found && (e = readdir(dir))) {
    if(e->d_name[0] == '.') continue;
    int slot = openat(game, e->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if(slot < 0) continue;
    found = same_backup_volume(slot) && (!latest || sm_ps5save_valid_stamp(slot)) &&
        legacy_slot_data(slot, 0);
    close(slot);
  }
  closedir(dir);
  return found;
}

static int
prune_legacy_game(const char *saves, const char *platform, const char *uid,
                  const char *title, bool latest, unsigned *kept) {
  char parent[128];
  snprintf(parent, sizeof parent, "%s/%s/%s", saves, platform, uid);
  int fd = open_backup_dir(parent);
  if(fd < 0) return errno == ENOENT ? 0 : -1;
  int game = openat(fd, title, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  int rc = 0;
  if(game >= 0) {
    if(legacy_game_usable(game, latest) && ++*kept > VERSIONS_TO_KEEP)
      rc = remove_backup_tree(fd, title, 0);
    close(game);
  }
  close(fd);
  return rc;
}

static int
prune_game_versions(const char *platform, const char *uid, const char *title,
                    const version_list_t *dates) {
  char path[128];
  snprintf(path, sizeof path, SM_PS5SAVE_VERSIONS "/%s/%s/%s", platform, uid, title);
  int fd = open_backup_dir(path);
  unsigned kept = 0;
  int rc = 0;
  if(fd >= 0) {
    version_list_t list = {0};
    rc = list_versions(fd, sm_ps5save_version_name, &list);
    if(!rc) {
      for(size_t i = 0; i < list.count; i++) {
        if(completed_at(fd, list.names[i]) && ++kept > VERSIONS_TO_KEEP &&
           remove_backup_tree(fd, list.names[i], 0))
          rc = -1;
      }
      if(remove_backup_tree(fd, VERSION_STAGING, 0)) rc = -1;
    }
    free(list.names);
    close(fd);
  } else if(errno != ENOENT) rc = -1;
  if(rc) return rc;

  if(prune_legacy_game(BACKUP_ROOT "/saves", platform, uid, title, true, &kept))
    rc = -1;
  for(size_t i = 0; i < dates->count && !interrupted(); i++) {
    snprintf(path, sizeof path, LEGACY_DAILY_ROOT "/%s/saves", dates->names[i]);
    if(prune_legacy_game(path, platform, uid, title, false, &kept)) rc = -1;
  }
  return rc;
}

static int
legacy_dates(version_list_t *dates) {
  int fd = open_backup_dir(LEGACY_DAILY_ROOT);
  if(fd < 0) return errno == ENOENT ? 0 : -1;
  int rc = list_versions(fd, sm_ps5save_legacy_date, dates);
  close(fd);
  return rc;
}

static int
prune_saved_games(const char *saves, const version_list_t *dates) {
  int rc = 0;
  const char *platforms[] = {"ps4", "ps5"};
  for(size_t p = 0; p < 2 && !interrupted(); p++) {
    const char *platform = platforms[p];
    char folder[128];
    snprintf(folder, sizeof folder, "%s/%s", saves, platform);
    int fd = open_backup_dir(folder);
    if(fd < 0) {
      if(errno != ENOENT) rc = -1;
      continue;
    }
    DIR *users = fdopendir(fd);
    if(!users) {
      close(fd);
      return -1;
    }
    const struct dirent *u;
    while(!interrupted() && (u = readdir(users))) {
      if(!is_hex_name(u->d_name)) continue;
      /* Collect title names before pruning. A legacy title can be removed
       * from this same directory. */
      int user = openat(fd, u->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
      if(user < 0) continue;
      version_list_t games = {0};
      if(same_backup_volume(user)) {
        if(list_versions(user, title_valid, &games)) rc = -1;
        else for(size_t i = 0; i < games.count && !interrupted(); i++) {
          if(prune_game_versions(platform, u->d_name, games.names[i], dates))
            rc = -1;
        }
      }
      free(games.names);
      close(user);
    }
    closedir(users);
  }
  return rc;
}

static int
prune_all_versions(void) {
  version_list_t dates = {0};
  int rc = legacy_dates(&dates);
  if(!rc) {
    if(prune_saved_games(SM_PS5SAVE_VERSIONS, &dates)) rc = -1;
    if(prune_saved_games(BACKUP_ROOT "/saves", &dates)) rc = -1;
    for(size_t i = 0; i < dates.count && !interrupted(); i++) {
      char path[64];
      snprintf(path, sizeof path, LEGACY_DAILY_ROOT "/%s/saves", dates.names[i]);
      if(prune_saved_games(path, &dates)) rc = -1;
    }
  }
  free(dates.names);
  return rc;
}
