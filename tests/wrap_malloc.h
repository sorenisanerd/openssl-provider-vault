#pragma once
#include <stddef.h>

/*
 * Fail-on-Nth-allocation helpers for OOM testing via -Wl,--wrap,malloc
 * and -Wl,--wrap,calloc.  Only malloc/calloc from compiled-in source files
 * are intercepted; calls inside shared libraries (libcrypto, libcurl, etc.)
 * go directly to the real allocator and are unaffected.
 *
 * wrap_malloc_fail_after(n): let the next n calls succeed, then fail once.
 *   n=0 fails the very next allocation.
 *   The counter resets to "pass-through" automatically after the failure.
 *
 * wrap_malloc_reset(): cancel any pending failure (safe to call unconditionally).
 */
void wrap_malloc_fail_after(int n);
void wrap_malloc_reset(void);
