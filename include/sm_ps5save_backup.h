#ifndef SM_PS5SAVE_BACKUP_H
#define SM_PS5SAVE_BACKUP_H

#include <stdbool.h>
#include <stdint.h>

#define SM_PS5SAVE_MAX_INTERVAL_MINUTES 1440

typedef struct {
  const char *state;
  long interval_seconds;
  int64_t last_copy_at;
  bool last_copy_ok;
  bool ps4;
  bool ps5;
  bool trophies;
  bool configured;
  bool enabled;
  bool busy;
} sm_ps5save_backup_status_t;

bool sm_ps5save_backup_start(void);
void sm_ps5save_backup_stop(void);
sm_ps5save_backup_status_t sm_ps5save_backup_status(void);
int sm_ps5save_backup_request(void);
int sm_ps5save_backup_set_enabled(bool enabled);
int sm_ps5save_backup_set_interval(long minutes);
bool sm_ps5save_try_begin_restore(void);
void sm_ps5save_end_restore(void);

#endif
