#ifndef SM_PS5SAVE_RESTORE_H
#define SM_PS5SAVE_RESTORE_H
#include <stddef.h>
struct json_object;

/* PS5Save on the internal M.2, matching PS5Upload-12.4.20-PS5Save-M2. */
#define SM_PS5SAVE_VOLUME "/mnt/ext1"
typedef struct {
  char user[9];
  char backup_user[9];
  char title_id[10];
  char platform[4];
  char version[11];
  char slot[200];
  char image[200];
} sm_ps5save_request_t;

/* Validation and safe openat traversal from the known-working PS5Upload fork. */
int sm_ps5save_restore_image(const sm_ps5save_request_t *r, char *path, size_t cap);
int sm_ps5save_open_slot(int volume, const sm_ps5save_request_t *r);
int sm_ps5save_copy_slot(int source, int destination, int latest);

/* ShadowMountPlus-native integration; PS5Upload does not have to be running. */
struct json_object *sm_ps5save_catalog(const char *user);
int sm_ps5save_restore(const sm_ps5save_request_t *r, const char **reason);
#endif
