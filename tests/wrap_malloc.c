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
