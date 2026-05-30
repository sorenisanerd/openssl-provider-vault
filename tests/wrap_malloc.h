/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Soren L. Hansen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
