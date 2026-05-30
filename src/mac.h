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

#ifndef VAULT_MAC_H
#define VAULT_MAC_H

#include <stddef.h>
#include <openssl/core_dispatch.h>

void *vault_mac_newctx(void *provctx);
void  vault_mac_freectx(void *ctx);
void *vault_mac_dupctx(void *ctx);

int vault_mac_init_skey(void *ctx, const void *key,
                        const OSSL_PARAM params[]);
int vault_mac_update(void *ctx, const unsigned char *in, size_t inlen);
int vault_mac_final(void *ctx, unsigned char *out, size_t *outlen,
                    size_t outsize);

int               vault_mac_get_ctx_params(void *ctx, OSSL_PARAM params[]);
const OSSL_PARAM *vault_mac_gettable_ctx_params(void *ctx, void *provctx);
int               vault_mac_set_ctx_params(void *ctx,
                                            const OSSL_PARAM params[]);
const OSSL_PARAM *vault_mac_settable_ctx_params(void *ctx, void *provctx);

#endif /* VAULT_MAC_H */
