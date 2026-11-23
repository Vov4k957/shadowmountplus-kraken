/*
 * Read-only PS5Save M.2 catalog for the ShadowMountPlus web page.
 * Reads the integrated per-game versions and the older PS5Save layout:
 * backup/saves/{ps5|ps4}/<backup-user>/<title>/<slot> and
 * backup_daily/YYYY-MM-DD/saves/...
 */
#include "sm_platform.h"
#include "sm_ps5save_restore.h"
#include <json-c/json.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/stat.h>

#define SMP_CATALOG_LIMIT 512u
int sceUserServiceGetUserName(int user_id, char *name, size_t max_size);
int sceUserServiceGetForegroundUser(int *user_id);
typedef struct {
  struct json_object *items;
  const char *selected_user;
  size_t count;
  bool truncated;
} catalog_t;
static int safe_name(const char *name) {
  if (!name || !*name || name[0] == '.' || strlen(name) >= 200) return 0;
  for (const unsigned char *p = (const unsigned char *)name; *p; ++p)
    if (*p < 32 || *p == 127 || *p == '/' || *p == '\\') return 0;
  return 1;
}
static int hex_name(const char *name, size_t min, size_t max) {
  size_t n = strlen(name);
  return n >= min && n <= max &&
      strspn(name, "0123456789abcdefABCDEF") == n;
}
static int game_name(const char *name) {
  return strlen(name) == 9 &&
      strspn(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 4 &&
      strspn(name + 4, "0123456789") == 5;
}
static bool is_directory_at(int dir, const char *name) {
  struct stat st;
  return fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
      S_ISDIR(st.st_mode);
}
static int directory_at(int fd, const char *name) {
  return openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
}
static int directory(const char *path) {
  return open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
}
static void append_item(catalog_t *c, const char *platform,
                        const char *user, const char *backup_user,
                        const char *title, const char *slot,
                        const char *version, const char *image) {
  if (c->count >= SMP_CATALOG_LIMIT) { c->truncated = true; return; }
  struct json_object *obj = json_object_new_object();
  if (!obj) { c->truncated = true; return; }
  json_object_object_add(obj, "platform", json_object_new_string(platform));
  json_object_object_add(obj, "user", json_object_new_string(user));
  json_object_object_add(obj, "backup_user", json_object_new_string(backup_user));
  json_object_object_add(obj, "title_id", json_object_new_string(title));
  json_object_object_add(obj, "slot", json_object_new_string(slot));
  json_object_object_add(obj, "version", json_object_new_string(version));
  if (image) json_object_object_add(obj, "image", json_object_new_string(image));
  json_object_array_add(c->items, obj);
  c->count++;
}
typedef struct {
  char (*images)[200];
  size_t count;
  size_t capacity;
  bool truncated;
} target_list_t;

static target_list_t load_targets(const catalog_t *c, const char *platform,
                                  const char *title) {
  target_list_t result = {0};
  if (!c->selected_user[0]) return result;
  const bool ps4 = strcmp(platform, "ps4") == 0;
  char path[512];
  int n = snprintf(path, sizeof(path), "/user/home/%s/%s/%s",
                   c->selected_user,
                   ps4 ? "savedata" : "savedata_prospero", title);
  int targets = n < 0 || (size_t)n >= sizeof(path) ? -1 : directory(path);
  DIR *dir = targets >= 0 ? fdopendir(targets) : NULL;
  if (!dir) {
    if (targets >= 0) close(targets);
    return result;
  }
  const struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    const char *image = entry->d_name;
    const bool prefixed = strncmp(image, "sdimg_", 6) == 0;
    const char *slot_name = prefixed ? image + 6 : image;
    if (!safe_name(image) || !safe_name(slot_name) || !strncmp(slot_name, "sce_bu_", 7) ||
        (ps4 && !prefixed)) continue;
    size_t len = strlen(image);
    if ((len >= 4 && !strcmp(image + len - 4, ".bin")) ||
        (len >= 8 && !strcmp(image + len - 8, ".unsaved")) ||
        (len >= 10 && !strcmp(image + len - 10, ".ps5up-tmp")) ||
        (len >= 8 && !strcmp(image + len - 8, ".smp-new")))
      continue;
    struct stat st;
    if (fstatat(targets, image, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(st.st_mode)) continue;
    if (ps4) {
      char key[204];
      snprintf(key, sizeof key, "%s.bin", slot_name);
      if (fstatat(targets, key, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
          !S_ISREG(st.st_mode)) continue;
    }
    if (result.count >= SMP_CATALOG_LIMIT) {
      result.truncated = true;
      break;
    }
    if (result.count == result.capacity) {
      size_t capacity = result.capacity ? result.capacity * 2 : 8;
      void *next = realloc(result.images, capacity * sizeof *result.images);
      if (!next) {
        result.truncated = true;
        break;
      }
      result.images = next;
      result.capacity = capacity;
    }
    strcpy(result.images[result.count++], image);
  }
  closedir(dir);
  return result;
}

static void append_slot(catalog_t *c, const target_list_t *targets,
                        const char *platform, const char *backup_user,
                        const char *title, const char *slot, const char *version) {
  if (!targets->count) {
    append_item(c, platform, c->selected_user, backup_user, title,
                slot, version, NULL);
    return;
  }
  for (size_t i = 0; i < targets->count && !c->truncated; i++) {
    const char *image = targets->images[i];
    const char *name = strncmp(image, "sdimg_", 6) == 0 ? image + 6 : image;
    if (strcmp(name, slot) == 0) {
      append_item(c, platform, c->selected_user, backup_user, title, slot, version, image);
      return;
    }
  }
  for (size_t i = 0; i < targets->count && !c->truncated; i++)
    append_item(c, platform, c->selected_user, backup_user, title, slot,
                version, targets->images[i]);
}

static void scan_slots(catalog_t *c, int title_fd, const char *platform,
                       const char *backup_user, const char *title,
                       const char *version) {
  int dup_fd = dup(title_fd);
  if (dup_fd < 0) return;
  DIR *slots = fdopendir(dup_fd);
  if (!slots) { close(dup_fd); return; }
  target_list_t targets = load_targets(c, platform, title);
  const struct dirent *s;
  while ((s = readdir(slots)) != NULL && !c->truncated) {
    if (!safe_name(s->d_name) ||
        !is_directory_at(title_fd, s->d_name)) continue;
    int slotfd = directory_at(title_fd, s->d_name);
    if (slotfd < 0) continue;
    bool valid = sm_ps5save_legacy_date(version) || sm_ps5save_valid_stamp(slotfd);
    close(slotfd);
    if (valid)
      append_slot(c, &targets, platform, backup_user, title, s->d_name, version);
  }
  closedir(slots);
  c->truncated = c->truncated || targets.truncated;
  free(targets.images);
}

static void scan_game_versions(catalog_t *c, int title_fd, const char *platform,
                               const char *backup_user, const char *title) {
  int fd = directory_at(title_fd, ".");
  if (fd < 0) return;
  DIR *versions = fdopendir(fd);
  if (!versions) { close(fd); return; }
  const struct dirent *e;
  while ((e = readdir(versions)) != NULL && !c->truncated) {
    if (!sm_ps5save_version_name(e->d_name)) continue;
    int version_fd = directory_at(title_fd, e->d_name);
    if (version_fd < 0) continue;
    if (sm_ps5save_complete_version(version_fd))
      scan_slots(c, version_fd, platform, backup_user, title, e->d_name);
    close(version_fd);
  }
  closedir(versions);
}

static void scan_titles(catalog_t *c, int user_fd, const char *platform,
                        const char *backup_user, const char *version) {
  int dup_fd = dup(user_fd);
  if (dup_fd < 0) return;
  DIR *titles = fdopendir(dup_fd);
  if (!titles) { close(dup_fd); return; }
  const struct dirent *e;
  while ((e = readdir(titles)) != NULL && !c->truncated) {
    if (!game_name(e->d_name)) continue;
    int title_fd = directory_at(user_fd, e->d_name);
    if (title_fd >= 0) {
      if (version) scan_slots(c, title_fd, platform, backup_user, e->d_name, version);
      else scan_game_versions(c, title_fd, platform, backup_user, e->d_name);
      close(title_fd);
    }
  }
  closedir(titles);
}
static void scan_users(catalog_t *c, int platform_fd,
                       const char *platform, const char *version) {
  int dup_fd = dup(platform_fd);
  if (dup_fd < 0) return;
  DIR *users = fdopendir(dup_fd);
  if (!users) { close(dup_fd); return; }
  const struct dirent *e;
  while ((e = readdir(users)) != NULL && !c->truncated) {
    if (!hex_name(e->d_name, 1, 8)) continue;
    int userfd = directory_at(platform_fd, e->d_name);
    if (userfd >= 0) {
      scan_titles(c, userfd, platform, e->d_name, version);
      close(userfd);
    }
  }
  closedir(users);
}
static void scan_version(catalog_t *c, int volume, const char *version) {
  char path[512];
  int n;
  if (!version)
    n = snprintf(path, sizeof(path), "PS5Save/" SM_PS5SAVE_VERSIONS);
  else if (!strcmp(version, "latest"))
    n = snprintf(path, sizeof(path), "PS5Save/backup/saves");
  else
    n = snprintf(path, sizeof(path), "PS5Save/backup_daily/%s/saves", version);
  if (n < 0 || (size_t)n >= sizeof(path)) return;
  int saves = sm_ps5save_open_dir(volume, path);
  if (saves < 0) return;
  for (size_t i = 0; i < 2 && !c->truncated; ++i) {
    const char *platform = i == 0 ? "ps5" : "ps4";
    int fd = directory_at(saves, platform);
    if (fd >= 0) {
      scan_users(c, fd, platform, version);
      close(fd);
    }
  }
  close(saves);
}
struct json_object *sm_ps5save_catalog(const char *user) {
  struct json_object *root = json_object_new_object();
  struct json_object *users = json_object_new_array();
  struct json_object *items = json_object_new_array();
  if (!root || !users || !items) {
    if (root) json_object_put(root);
    if (users) json_object_put(users);
    if (items) json_object_put(items);
    return NULL;
  }
  char selected[9] = {0};
  char foreground[9] = {0};
  char requested[9] = {0};
  bool valid_user = user && hex_name(user, 8, 8);
  int foreground_id = 0;
  if (sceUserServiceGetForegroundUser(&foreground_id) == 0)
    snprintf(foreground, sizeof foreground, "%08x", (unsigned int)foreground_id);
  int homes = directory("/user/home");
  if (homes >= 0) {
    DIR *dir = fdopendir(homes);
    if (dir) {
      const struct dirent *e;
      while ((e = readdir(dir)) != NULL) {
        if (hex_name(e->d_name, 8, 8) &&
            is_directory_at(homes, e->d_name)) {
          struct json_object *profile = json_object_new_object();
          if (!profile) continue;
          char name[64] = {0};
          int user_id = (int)strtoul(e->d_name, NULL, 16);
          if (sceUserServiceGetUserName(user_id, name, sizeof name) != 0)
            name[0] = '\0';
          name[sizeof name - 1] = '\0';
          json_object_object_add(profile, "id", json_object_new_string(e->d_name));
          json_object_object_add(profile, "name", json_object_new_string(name));
          json_object_array_add(users, profile);
          if (!selected[0] || !strcmp(foreground, e->d_name))
            snprintf(selected, sizeof selected, "%s", e->d_name);
          if (valid_user && !strcmp(user, e->d_name))
            snprintf(requested, sizeof requested, "%s", e->d_name);
        }
      }
      closedir(dir);
    } else close(homes);
  }
  if (requested[0]) memcpy(selected, requested, sizeof selected);
  catalog_t c = {.items = items, .selected_user = selected,
                 .count = 0, .truncated = false};
  int volume = open(SM_PS5SAVE_VOLUME, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  bool mounted = false;
  if (volume >= 0) {
    struct statfs st;
    mounted = fstatfs(volume, &st) == 0 &&
        strcmp(st.f_mntonname, SM_PS5SAVE_VOLUME) == 0;
  }
  if (mounted) {
    scan_version(&c, volume, NULL);
    scan_version(&c, volume, "latest");
    int dfd = sm_ps5save_open_dir(volume, "PS5Save/backup_daily");
    if (dfd >= 0) {
      DIR *dates = fdopendir(dfd);
      if (dates) {
        const struct dirent *e;
        while ((e = readdir(dates)) != NULL && !c.truncated) {
          if (sm_ps5save_legacy_date(e->d_name) && is_directory_at(dfd, e->d_name))
            scan_version(&c, volume, e->d_name);
        }
        closedir(dates);
      } else close(dfd);
    }
  }
  if (volume >= 0) close(volume);
  json_object_object_add(root, "status", json_object_new_int(0));
  json_object_object_add(root, "mounted", json_object_new_boolean(mounted));
  json_object_object_add(root, "selected_user", json_object_new_string(selected));
  json_object_object_add(root, "users", users);
  json_object_object_add(root, "items", items);
  json_object_object_add(root, "truncated", json_object_new_boolean(c.truncated));
  json_object_object_add(root, "root", json_object_new_string(SM_PS5SAVE_VOLUME "/PS5Save"));
  return root;
}
