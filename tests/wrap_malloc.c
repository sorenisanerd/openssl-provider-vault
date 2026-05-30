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

#include "wrap_malloc.h"
#include <stddef.h>

extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t nmemb, size_t size);

static int g_countdown = -1;   /* -1 = pass-through always */

void wrap_malloc_fail_after(int n) { g_countdown = n; }
void wrap_malloc_reset(void)       { g_countdown = -1; }

static int tick(void)
{
    if (g_countdown < 0)
        return 0;
    if (g_countdown == 0) {
        g_countdown = -1;
        return 1;
    }
    --g_countdown;
    return 0;
}

void *__wrap_malloc(size_t size)
{
    return tick() ? NULL : __real_malloc(size);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
    return tick() ? NULL : __real_calloc(nmemb, size);
}
