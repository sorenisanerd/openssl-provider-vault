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

#include "keymgmt.h"
#include "provider.h"
#include "vault_client.h"
#include "vault_keyref.h"
#include "vault_format.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>

/* Custom param name for the Vault key name during gen. */
#define VAULT_PARAM_KEY_NAME  "vault-key-name"
#define VAULT_PARAM_EXPORTABLE "vault-exportable"

struct vault_keymgmt_genctx {
    vault_provctx_t *provctx;
    int              pkey_type;    /* EVP_PKEY_RSA, EVP_PKEY_EC, etc. */
    int              bits;         /* RSA key size                     */
    int              curve_nid;    /* EC curve NID                     */
    char            *key_name;     /* required vault-key-name param    */
    int              exportable;
};

void *vault_keymgmt_new(void *provctx)
{
    /* A new empty key slot — not yet populated. */
    (void)provctx;
    return calloc(1, sizeof(vault_keyref_t));
}

void vault_keymgmt_free(void *keydata)
{
    vault_keyref_free((vault_keyref_t *)keydata);
}

int vault_keymgmt_has(const void *keydata, int selection)
{
    const vault_keyref_t *ref = (const vault_keyref_t *)keydata;
    if (!ref || !ref->key_name)
        return 0;

    /*
     * The private key lives in Vault — we never hold raw private material
     * locally, but the key does exist and can perform private-key operations
     * (sign, decrypt) via the Vault API.
     */
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 1;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return ref->pubkey_der != NULL && ref->pubkey_der_len > 0;

    return 1;
}

void *vault_keymgmt_load(const void *reference, size_t reference_sz)
{
    return vault_keyref_deserialize((const unsigned char *)reference,
                                    reference_sz);
}

int vault_keymgmt_export(void *keydata, int selection,
                          OSSL_CALLBACK *param_cb, void *cbarg)
{
    vault_keyref_t *ref = (vault_keyref_t *)keydata;

    if (!ref || !ref->key_name)
        return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 0;   /* private key material never leaves Vault */

    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 1;   /* nothing requested */

    if (!ref->pubkey_der || !ref->pubkey_der_len)
        return 0;

    /* Parse the DER-encoded SubjectPublicKeyInfo we cached from Vault. */
    const unsigned char *p = ref->pubkey_der;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)ref->pubkey_der_len);
    if (!pkey)
        return 0;

    /*
     * EVP_PKEY_todata exports the public key as an OSSL_PARAM array using
     * algorithm-specific parameter names (OSSL_PKEY_PARAM_RSA_N/E for RSA,
     * OSSL_PKEY_PARAM_PUB_KEY + group for EC, etc.).
     */
    OSSL_PARAM *params = NULL;
    int rv = 0;
    if (EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY, &params) == 1) {
        rv = param_cb(params, cbarg);
        OSSL_PARAM_free(params);
    }
    EVP_PKEY_free(pkey);
    return rv;
}

int vault_keymgmt_import(void *keydata, int selection,
                          const OSSL_PARAM params[])
{
    /* TODO: accept public key material import */
    (void)keydata;
    (void)selection;
    (void)params;
    return 0;
}

const OSSL_PARAM *vault_keymgmt_import_types(int selection)
{
    (void)selection;
    static const OSSL_PARAM types[] = { OSSL_PARAM_END };
    return types;
}

const OSSL_PARAM *vault_keymgmt_export_types(int selection)
{
    (void)selection;
    static const OSSL_PARAM types[] = { OSSL_PARAM_END };
    return types;
}

const char *vault_keymgmt_query_operation_name(int operation_id)
{
    (void)operation_id;
    return "RSA";
}

/* ── get/settable params ──────────────────────────────────────────────── */

static int key_bits_from_type(const char *key_type)
{
    if (!key_type) return 0;
    if (strncmp(key_type, "rsa-", 4) == 0) return atoi(key_type + 4);
    if (strcmp(key_type, "ecdsa-p256") == 0) return 256;
    if (strcmp(key_type, "ecdsa-p384") == 0) return 384;
    if (strcmp(key_type, "ecdsa-p521") == 0) return 521;
    if (strcmp(key_type, "ed25519")    == 0) return 255;
    return 0;
}

const OSSL_PARAM *vault_keymgmt_gettable_params(void *provctx)
{
    (void)provctx;
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };
    return gettable;
}

int vault_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    vault_keyref_t *ref = (vault_keyref_t *)keydata;
    OSSL_PARAM *p;

    if (!ref || !ref->key_name)
        return 1;   /* empty key — nothing to return */

    int bits = key_bits_from_type(ref->key_type);

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p && !OSSL_PARAM_set_int(p, bits))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p) {
        /* Rough estimate: RSA security ≈ bits/10, EC/Ed ≈ bits/2. */
        int sec = (strncmp(ref->key_type, "rsa-", 4) == 0) ? bits / 10
                                                             : bits / 2;
        if (!OSSL_PARAM_set_int(p, sec))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p) {
        /* Signature size upper bound: RSA = key bytes, EC ≈ 2*key bytes. */
        int max = (strncmp(ref->key_type, "rsa-", 4) == 0) ? bits / 8
                                                             : (bits / 4) + 8;
        if (!OSSL_PARAM_set_int(p, max))
            return 0;
    }

    return 1;
}

/* ── gen lifecycle ────────────────────────────────────────────────────── */

void *vault_keymgmt_gen_init(void *provctx, int selection,
                              const OSSL_PARAM params[])
{
    (void)selection;
    struct vault_keymgmt_genctx *gctx = calloc(1, sizeof(*gctx));
    if (!gctx)
        return NULL;
    gctx->provctx = (vault_provctx_t *)provctx;

    if (params)
        vault_keymgmt_gen_set_params(gctx, params);

    return gctx;
}

/* Type-specific gen_init wrappers — set pkey_type and sensible defaults. */

void *vault_rsa_keymgmt_gen_init(void *provctx, int selection,
                                   const OSSL_PARAM params[])
{
    struct vault_keymgmt_genctx *gctx =
        vault_keymgmt_gen_init(provctx, selection, params);
    if (gctx) {
        gctx->pkey_type = EVP_PKEY_RSA;
        if (!gctx->bits)
            gctx->bits = 2048;
    }
    return gctx;
}

void *vault_ec_keymgmt_gen_init(void *provctx, int selection,
                                  const OSSL_PARAM params[])
{
    struct vault_keymgmt_genctx *gctx =
        vault_keymgmt_gen_init(provctx, selection, params);
    if (gctx) {
        gctx->pkey_type = EVP_PKEY_EC;
        if (!gctx->curve_nid)
            gctx->curve_nid = NID_X9_62_prime256v1;   /* default P-256 */
    }
    return gctx;
}

void *vault_ed25519_keymgmt_gen_init(void *provctx, int selection,
                                      const OSSL_PARAM params[])
{
    struct vault_keymgmt_genctx *gctx =
        vault_keymgmt_gen_init(provctx, selection, params);
    if (gctx)
        gctx->pkey_type = EVP_PKEY_ED25519;
    return gctx;
}

static const OSSL_PARAM gen_settable[] = {
    OSSL_PARAM_utf8_string(VAULT_PARAM_KEY_NAME, NULL, 0),
    OSSL_PARAM_uint(OSSL_PKEY_PARAM_RSA_BITS, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_int(VAULT_PARAM_EXPORTABLE, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM *vault_keymgmt_gen_settable_params(void *genctx,
                                                      void *provctx)
{
    (void)genctx;
    (void)provctx;
    return gen_settable;
}

int vault_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct vault_keymgmt_genctx *gctx = (struct vault_keymgmt_genctx *)genctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, VAULT_PARAM_KEY_NAME);
    if (p) {
        free(gctx->key_name);
        gctx->key_name = NULL;
        OSSL_PARAM_get_utf8_string(p, &gctx->key_name, 0);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
    if (p)
        OSSL_PARAM_get_uint(p, (unsigned int *)&gctx->bits);

    p = OSSL_PARAM_locate_const(params, VAULT_PARAM_EXPORTABLE);
    if (p)
        OSSL_PARAM_get_int(p, &gctx->exportable);

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p) {
        char grp[64] = {0};
        char *gp = grp;
        if (OSSL_PARAM_get_utf8_string(p, &gp, sizeof(grp))) {
            /* Try NIST short name first (P-256, P-384, P-521), then OID text. */
            int nid = EC_curve_nist2nid(grp);
            if (nid == NID_undef)
                nid = OBJ_txt2nid(grp);
            if (nid != NID_undef)
                gctx->curve_nid = nid;
        }
    }

    return 1;
}

void *vault_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    struct vault_keymgmt_genctx *gctx = (struct vault_keymgmt_genctx *)genctx;
    (void)cb;
    (void)cbarg;

    if (!gctx->key_name || gctx->key_name[0] == '\0')
        return NULL;   /* vault-key-name is mandatory */

    const char *vault_type = vault_key_type_name(gctx->pkey_type,
                                                   gctx->bits,
                                                   gctx->curve_nid);
    if (!vault_type)
        return NULL;

    if (vault_create_key(gctx->provctx->vault,
                         gctx->key_name, vault_type,
                         gctx->exportable) != 0)
        return NULL;

    /* Fetch fresh key metadata (including public key DER). */
    vault_key_info_t info = {0};
    if (vault_get_key(gctx->provctx->vault, gctx->key_name, &info) != 0)
        return NULL;

    vault_keyref_t *ref = vault_keyref_new(gctx->key_name,
                                            info.latest_version,
                                            info.key_type,
                                            info.pubkey_der,
                                            info.pubkey_der_len);
    vault_key_info_free(&info);
    return ref;
}

void vault_keymgmt_gen_cleanup(void *genctx)
{
    struct vault_keymgmt_genctx *gctx = (struct vault_keymgmt_genctx *)genctx;
    if (!gctx)
        return;
    free(gctx->key_name);
    free(gctx);
}
