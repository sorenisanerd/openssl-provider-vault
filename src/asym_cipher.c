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

#include "asym_cipher.h"
#include "provider.h"
#include "vault_client.h"
#include "vault_keyref.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/params.h>

typedef struct {
    vault_provctx_t *provctx;
    vault_keyref_t  *key;   /* borrowed — not owned */
} vault_asym_cipher_ctx_t;

void *vault_asym_cipher_newctx(void *provctx, const char *propq)
{
    (void)propq;
    vault_asym_cipher_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->provctx = (vault_provctx_t *)provctx;
    return ctx;
}

void vault_asym_cipher_freectx(void *ctx)
{
    free(ctx);
}

void *vault_asym_cipher_dupctx(void *ctx)
{
    vault_asym_cipher_ctx_t *src = (vault_asym_cipher_ctx_t *)ctx;
    vault_asym_cipher_ctx_t *dst = malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    return dst;
}

int vault_asym_cipher_encrypt_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[])
{
    (void)params;
    vault_asym_cipher_ctx_t *actx = (vault_asym_cipher_ctx_t *)ctx;
    actx->key = (vault_keyref_t *)provkey;
    return 1;
}

int vault_asym_cipher_encrypt(void *ctx,
                               unsigned char *out, size_t *outlen,
                               size_t outsize,
                               const unsigned char *in, size_t inlen)
{
    vault_asym_cipher_ctx_t *actx = (vault_asym_cipher_ctx_t *)ctx;

    if (!out) {
        *outlen = 4096;
        return 1;
    }

    unsigned char *ct = NULL;
    size_t         ct_len = 0;

    if (vault_asym_encrypt(actx->provctx->vault,
                           actx->key->key_name,
                           actx->key->key_version,
                           in, inlen,
                           &ct, &ct_len) != 0)
        return 0;

    if (ct_len > outsize) {
        free(ct);
        return 0;
    }

    memcpy(out, ct, ct_len);
    *outlen = ct_len;
    free(ct);
    return 1;
}

int vault_asym_cipher_decrypt_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[])
{
    (void)params;
    vault_asym_cipher_ctx_t *actx = (vault_asym_cipher_ctx_t *)ctx;
    actx->key = (vault_keyref_t *)provkey;
    return 1;
}

int vault_asym_cipher_decrypt(void *ctx,
                               unsigned char *out, size_t *outlen,
                               size_t outsize,
                               const unsigned char *in, size_t inlen)
{
    vault_asym_cipher_ctx_t *actx = (vault_asym_cipher_ctx_t *)ctx;

    if (!out) {
        *outlen = 4096;
        return 1;
    }

    unsigned char *pt = NULL;
    size_t         pt_len = 0;

    if (vault_asym_decrypt(actx->provctx->vault,
                           actx->key->key_name,
                           actx->key->key_version,
                           in, inlen,
                           &pt, &pt_len) != 0)
        return 0;

    if (pt_len > outsize) {
        free(pt);
        return 0;
    }

    memcpy(out, pt, pt_len);
    *outlen = pt_len;
    free(pt);
    return 1;
}

static const OSSL_PARAM gettable_ctx_params[] = {
    OSSL_PARAM_END
};

const OSSL_PARAM *vault_asym_cipher_gettable_ctx_params(void *ctx,
                                                         void *provctx)
{
    (void)ctx; (void)provctx;
    return gettable_ctx_params;
}

int vault_asym_cipher_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    (void)ctx; (void)params;
    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_END
};

const OSSL_PARAM *vault_asym_cipher_settable_ctx_params(void *ctx,
                                                         void *provctx)
{
    (void)ctx; (void)provctx;
    return settable_ctx_params;
}

int vault_asym_cipher_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    (void)ctx; (void)params;
    return 1;
}
