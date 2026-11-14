#ifndef SM_KRAKEN_H
#define SM_KRAKEN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sm_pkg.h"

#define SM_KRAKEN_PACKAGE_DIR "kraken"

bool sm_kraken_is_package(const char *path);
bool sm_kraken_is_cache(const char *path);
// Header check only. The full parser runs when the scanner prepares a cache.
bool sm_kraken_can_mount(const sm_pkg_info_t *info);
// Reuse a matching cache or build a complete new cache before publishing it.
bool sm_kraken_prepare(const sm_pkg_info_t *info, char cache[MAX_PATH]);
// Read the backing package path from an SMP Kraken cache, even if it is offline.
bool sm_kraken_source(const char *cache, char path[MAX_PATH]);
// Ejects and manual removals check the backing source without traversing the cache.
bool sm_kraken_source_ready(const char *cache);

#endif
