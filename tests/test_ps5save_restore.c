/*
 * Host-only safety fixtures for the PS5Upload 12.4.20 M.2 slot engine port.
 * No Sony mount functions or PS5 are required for this test.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "sm_ps5save_restore.h"
#include <assert.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void dirs(int root, const char *path) {
  char sub[256];
  assert(strlen(path) < sizeof sub);
  strcpy(sub, path);
  for (char *p = sub; (p = strchr(p, '/')) != NULL; ++p) {
    *p = 0;
    (void)mkdirat(root, sub, 0700);
    *p = '/';
  }
  assert(mkdirat(root, path, 0700) == 0);
}
static void put(int dir, const char *name, const void *bytes, size_t size) {
  int fd = openat(dir, name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  assert(fd >= 0);
  assert(write(fd, bytes, size) == (ssize_t)size);
  assert(close(fd) == 0);
}
static void check(int dir, const char *name, const char *expected) {
  char data[80];
  int fd = openat(dir, name, O_RDONLY);
  assert(fd >= 0);
  assert(read(fd, data, sizeof data) == (ssize_t)strlen(expected));
  assert(memcmp(data, expected, strlen(expected)) == 0);
  close(fd);
}
static int rm(const char *path, const struct stat *st, int type, struct FTW *info) {
  (void)st; (void)type; (void)info;
  return remove(path);
}
int main(void) {
  char tmp[] = "/tmp/sm-ps5save.XXXXXX";
  assert(mkdtemp(tmp));
  int root = open(tmp, O_RDONLY | O_DIRECTORY);
  assert(root >= 0);
  sm_ps5save_request_t req = {
      .user="000000bb", .backup_user="000000aa", .title_id="PPSA02100",
      .platform="ps5", .version="latest", .slot="Global",
      .image="sdimg_Global"
  };
  char path[512];
  assert(sm_ps5save_restore_image(&req, path, sizeof path) == 0);
  assert(strcmp(path, "/user/home/000000bb/savedata_prospero/PPSA02100/sdimg_Global") == 0);
  strcpy(req.image, "sdimg_sce_bu_Global");
  assert(sm_ps5save_restore_image(&req, path, sizeof path) < 0);
  strcpy(req.image, "sdimg_Global");
  strcpy(req.slot, "../Global");
  assert(sm_ps5save_restore_image(&req, path, sizeof path) < 0);
  strcpy(req.slot, "Global");
  const char *latest="PS5Save/backup/saves/ps5/000000aa/PPSA02100/Global";
  const char *daily="PS5Save/backup_daily/2026-11-15/saves/ps5/000000aa/PPSA02100/Global";
  dirs(root, latest);
  dirs(root, daily);
  dirs(root, "staging/sce_sys");
  int source=openat(root,latest,O_RDONLY|O_DIRECTORY);
  int snapshot=openat(root,daily,O_RDONLY|O_DIRECTORY);
  int stage=openat(root,"staging",O_RDONLY|O_DIRECTORY);
  assert(source>=0 && snapshot>=0 && stage>=0);
  dirs(source,"sce_sys");
  dirs(source,"nested");
  put(source,"sce_sys/param.sfo","old profile",11);
  put(source,"progress.sav","progress",8);
  put(source,"nested/child","child",5);
  put(stage,"sce_sys/param.sfo","new profile",11);
  put(stage,"old_file","old",3);
  assert(sm_ps5save_open_slot(root,&req)<0);
  unsigned char stamp[64]="PS5IMG2\n";
  put(source,".image_stamp",stamp,sizeof stamp);
  int open_slot=sm_ps5save_open_slot(root,&req);
  assert(open_slot>=0);
  assert(sm_ps5save_copy_slot(open_slot,stage,1)==0);
  close(open_slot);
  check(stage,"sce_sys/param.sfo","new profile");
  check(stage,"progress.sav","progress");
  check(stage,"nested/child","child");
  assert(faccessat(stage,"old_file",F_OK,0)<0);
  assert(faccessat(stage,".image_stamp",F_OK,0)<0);
  put(source,".image_stamp.part",stamp,sizeof stamp);
  assert(sm_ps5save_copy_slot(source,stage,1)<0);
  unlinkat(source,".image_stamp.part",0);
  strcpy(req.version,"2026-11-15");
  put(snapshot,"progress.sav","older progress",14);
  open_slot=sm_ps5save_open_slot(root,&req);
  assert(open_slot>=0);
  assert(sm_ps5save_copy_slot(open_slot,stage,0)==0);
  close(open_slot);
  check(stage,"sce_sys/param.sfo","new profile");
  check(stage,"progress.sav","older progress");
  assert(symlinkat("/etc/passwd",snapshot,"symlink")==0);
  assert(sm_ps5save_copy_slot(snapshot,stage,0)<0);

  const char *versions = "PS5Save/" SM_PS5SAVE_VERSIONS "/ps5/000000aa/PPSA02100";
  const char *version = "v1795400080000000";
  char stored[256];
  assert(snprintf(stored, sizeof stored, "%s/%s/Global", versions, version) < (int)sizeof stored);
  dirs(root, stored);
  int complete_slot = sm_ps5save_open_dir(root, stored);
  assert(complete_slot >= 0);
  put(complete_slot, ".image_stamp", stamp, sizeof stamp);
  put(complete_slot, "progress.sav", "complete version", 16);
  strcpy(req.version, version);
  assert(sm_ps5save_open_slot(root, &req) < 0);
  int complete = openat(complete_slot, "..", O_RDONLY | O_DIRECTORY);
  assert(complete >= 0);
  put(complete, SM_PS5SAVE_COMPLETE, SM_PS5SAVE_COMPLETE_MAGIC,
      sizeof SM_PS5SAVE_COMPLETE_MAGIC - 1);
  open_slot = sm_ps5save_open_slot(root, &req);
  assert(open_slot >= 0);
  assert(sm_ps5save_copy_slot(open_slot, stage, 0) == 0);
  check(stage, "sce_sys/param.sfo", "new profile");
  check(stage, "progress.sav", "complete version");
  close(open_slot);
  close(complete);
  close(complete_slot);
  strcpy(req.version, "../v000000000000");
  assert(sm_ps5save_open_slot(root, &req) < 0);
  close(root);close(source);close(stage);close(snapshot);
  assert(nftw(tmp,rm,16,FTW_DEPTH|FTW_PHYS)==0);
  puts("SM+ PS5Save slot safety fixtures passed");
  return 0;
}
