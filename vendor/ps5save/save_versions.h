/* The worker holds the backup/restore lock while publishing or pruning. */
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
  int dup_fd = dup(fd);
  if(dup_fd < 0) return -1;
  DIR *dir = fdopendir(dup_fd);
  if(!dir) {
    close(dup_fd);
    return -1;
  }
  rewinddir(dir);
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

/* Rotation is limited to versions published by this worker. The older
 * PS5Save and PS5Upload folders can also hold manually copied saves. */
static int
prune_game_versions(const char *platform, const char *uid, const char *title) {
  char path[128];
  snprintf(path, sizeof path, SM_PS5SAVE_VERSIONS "/%s/%s/%s", platform, uid, title);
  int fd = open_backup_dir(path);
  if(fd < 0) return errno == ENOENT ? 0 : -1;
  unsigned kept = 0;
  version_list_t list = {0};
  int rc = list_versions(fd, sm_ps5save_version_name, &list);
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
  return rc;
}

static int
prune_all_versions(void) {
  int rc = 0;
  const char *platforms[] = {"ps4", "ps5"};
  for(size_t p = 0; p < 2 && !interrupted(); p++) {
    const char *platform = platforms[p];
    char folder[128];
    snprintf(folder, sizeof folder, SM_PS5SAVE_VERSIONS "/%s", platform);
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
      int user = openat(fd, u->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
      if(user < 0) continue;
      version_list_t games = {0};
      if(same_backup_volume(user)) {
        if(list_versions(user, title_valid, &games)) rc = -1;
        else for(size_t i = 0; i < games.count && !interrupted(); i++) {
          if(prune_game_versions(platform, u->d_name, games.names[i]))
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
