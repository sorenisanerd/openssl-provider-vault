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

#include "vault_store_uri.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char SCHEME[] = "vault:";
static const size_t SCHEME_LEN = sizeof(SCHEME) - 1;

int vault_uri_parse(const char *uri, vault_uri_t *out)
{
    if (!uri || !out)
        return -1;

    if (strncmp(uri, SCHEME, SCHEME_LEN) != 0)
        return -1;

    const char *rest = uri + SCHEME_LEN;
    if (*rest == '\0')
        return -1;                  /* empty key name */

    /* Split on '?' */
    const char *q = strchr(rest, '?');
    size_t name_len = q ? (size_t)(q - rest) : strlen(rest);

    if (name_len == 0)
        return -1;

    out->key_name = malloc(name_len + 1);
    if (!out->key_name)
        return -1;
    memcpy(out->key_name, rest, name_len);
    out->key_name[name_len] = '\0';

    out->version = 0;

    if (q) {
        /* Parse query string: only "version=N" is defined. */
        const char *p = q + 1;
        while (*p) {
            if (strncmp(p, "version=", 8) == 0) {
                char *end;
                long v = strtol(p + 8, &end, 10);
                if (end == p + 8 || v < 0) {
                    free(out->key_name);
                    return -1;
                }
                out->version = (int)v;
                p = end;
            } else {
                /* Skip unknown parameters. */
                const char *amp = strchr(p, '&');
                p = amp ? amp + 1 : p + strlen(p);
            }
            if (*p == '&') p++;
        }
    }

    return 0;
}

void vault_uri_free(vault_uri_t *uri)
{
    if (!uri)
        return;
    free(uri->key_name);
    uri->key_name = NULL;
    uri->version  = 0;
}

char *vault_uri_format(const char *key_name, int version)
{
    if (!key_name || *key_name == '\0')
        return NULL;

    char *out;
    if (version > 0) {
        /* "vault:<name>?version=<N>" */
        if (asprintf(&out, "vault:%s?version=%d", key_name, version) < 0)
            return NULL;
    } else {
        if (asprintf(&out, "vault:%s", key_name) < 0)
            return NULL;
    }
    return out;
}
