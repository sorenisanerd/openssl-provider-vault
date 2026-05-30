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

#ifndef VAULT_PROVIDER_INT_H
#define VAULT_PROVIDER_INT_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "vault_client.h"

/* Provider context — one per loaded provider instance. */
typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX           *libctx;
    vault_ctx_t            *vault;
} vault_provctx_t;

/* Entry point declared for completeness; defined in provider.c. */
OSSL_provider_init_fn OSSL_provider_init;

#endif /* VAULT_PROVIDER_INT_H */
