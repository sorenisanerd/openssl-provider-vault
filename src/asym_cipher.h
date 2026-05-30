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

#ifndef VAULT_ASYM_CIPHER_H
#define VAULT_ASYM_CIPHER_H

#include <stddef.h>
#include <openssl/core_dispatch.h>

void *vault_asym_cipher_newctx(void *provctx, const char *propq);
void  vault_asym_cipher_freectx(void *ctx);
void *vault_asym_cipher_dupctx(void *ctx);

int vault_asym_cipher_encrypt_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[]);
int vault_asym_cipher_encrypt(void *ctx,
                               unsigned char *out, size_t *outlen,
                               size_t outsize,
                               const unsigned char *in, size_t inlen);

int vault_asym_cipher_decrypt_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[]);
int vault_asym_cipher_decrypt(void *ctx,
                               unsigned char *out, size_t *outlen,
                               size_t outsize,
                               const unsigned char *in, size_t inlen);

int               vault_asym_cipher_get_ctx_params(void *ctx,
                                                    OSSL_PARAM params[]);
const OSSL_PARAM *vault_asym_cipher_gettable_ctx_params(void *ctx,
                                                         void *provctx);
int               vault_asym_cipher_set_ctx_params(void *ctx,
                                                    const OSSL_PARAM params[]);
const OSSL_PARAM *vault_asym_cipher_settable_ctx_params(void *ctx,
                                                         void *provctx);

#endif /* VAULT_ASYM_CIPHER_H */
