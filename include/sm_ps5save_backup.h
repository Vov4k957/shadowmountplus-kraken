#ifndef SM_PS5SAVE_BACKUP_H
#define SM_PS5SAVE_BACKUP_H

#include <stdbool.h>

typedef struct {
  const char *state;
  long interval_seconds;
  int daily_snapshots;
  bool ps4;
  bool ps5;
  bool enabled;
  bool busy;
} sm_ps5save_backup_status_t;

bool sm_ps5save_backup_start(void);
void sm_ps5save_backup_stop(void);
sm_ps5save_backup_status_t sm_ps5save_backup_status(void);
int sm_ps5save_backup_request(void);
int sm_ps5save_backup_set_enabled(bool enabled);
bool sm_ps5save_try_begin_restore(void);
void sm_ps5save_end_restore(void);

#endif
