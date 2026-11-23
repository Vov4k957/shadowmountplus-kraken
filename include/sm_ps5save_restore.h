#ifndef SM_PS5SAVE_RESTORE_H
#define SM_PS5SAVE_RESTORE_H
#include <stddef.h>
struct json_object;

/* PS5Save on the internal M.2, matching PS5Upload-12.4.20-PS5Save-M2. */
#define SM_PS5SAVE_VOLUME "/mnt/ext1"
#define SM_PS5SAVE_ROLLBACK "/data/ps5upload/save-backups"
#define SM_PS5SAVE_VERSIONS "backup_versions"
#define SM_PS5SAVE_VERSION_SIZE 18
#define SM_PS5SAVE_COMPLETE ".smp-complete"
#define SM_PS5SAVE_COMPLETE_MAGIC "SMP1\n"
typedef struct {
  char user[9];
  char backup_user[9];
  char title_id[10];
  char platform[4];
  char version[SM_PS5SAVE_VERSION_SIZE];
  char slot[200];
  char image[200];
} sm_ps5save_request_t;

/* Validation and safe openat traversal from the known-working PS5Upload fork. */
int sm_ps5save_restore_image(const sm_ps5save_request_t *r, char *path, size_t cap);
int sm_ps5save_open_slot(int volume, const sm_ps5save_request_t *r);
int sm_ps5save_copy_slot(int source, int destination, int latest);
int sm_ps5save_version_name(const char *name);
int sm_ps5save_legacy_date(const char *name);
int sm_ps5save_complete_version(int dir);
int sm_ps5save_valid_stamp(int slot);
int sm_ps5save_open_dir(int parent, const char *path);

struct json_object *sm_ps5save_catalog(const char *user);
int sm_ps5save_restore(const sm_ps5save_request_t *r, const char **reason,
                       char *backup, size_t backup_size);
#endif
