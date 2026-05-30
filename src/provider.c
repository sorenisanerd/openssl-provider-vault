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

#include "provider.h"
#include "keymgmt.h"
#include "signature.h"
#include "asym_cipher.h"
#include "mac.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ── forward declaration ─────────────────────────────────────────────── */

extern const OSSL_DISPATCH vault_store_funcs[];

/* ── KEYMGMT dispatch tables ─────────────────────────────────────────── */

#define KEYMGMT_COMMON_FNS(gen_init_fn)                                       \
    { OSSL_FUNC_KEYMGMT_NEW,                (void(*)(void))vault_keymgmt_new              }, \
    { OSSL_FUNC_KEYMGMT_FREE,               (void(*)(void))vault_keymgmt_free             }, \
    { OSSL_FUNC_KEYMGMT_HAS,                (void(*)(void))vault_keymgmt_has              }, \
    { OSSL_FUNC_KEYMGMT_LOAD,               (void(*)(void))vault_keymgmt_load             }, \
    { OSSL_FUNC_KEYMGMT_EXPORT,             (void(*)(void))vault_keymgmt_export           }, \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,       (void(*)(void))vault_keymgmt_export_types     }, \
    { OSSL_FUNC_KEYMGMT_IMPORT,             (void(*)(void))vault_keymgmt_import           }, \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,       (void(*)(void))vault_keymgmt_import_types     }, \
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,(void(*)(void))vault_keymgmt_query_operation_name }, \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,    (void(*)(void))vault_keymgmt_gettable_params  }, \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,         (void(*)(void))vault_keymgmt_get_params       }, \
    { OSSL_FUNC_KEYMGMT_GEN_INIT,           (void(*)(void))gen_init_fn                    }, \
    { OSSL_FUNC_KEYMGMT_GEN,                (void(*)(void))vault_keymgmt_gen              }, \
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,        (void(*)(void))vault_keymgmt_gen_cleanup      }, \
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,     (void(*)(void))vault_keymgmt_gen_set_params   }, \
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,(void(*)(void))vault_keymgmt_gen_settable_params }

static const OSSL_DISPATCH vault_rsa_keymgmt_funcs[] = {
    KEYMGMT_COMMON_FNS(vault_rsa_keymgmt_gen_init),
    { 0, NULL }
};

static const OSSL_DISPATCH vault_ec_keymgmt_funcs[] = {
    KEYMGMT_COMMON_FNS(vault_ec_keymgmt_gen_init),
    { 0, NULL }
};

static const OSSL_DISPATCH vault_ed25519_keymgmt_funcs[] = {
    KEYMGMT_COMMON_FNS(vault_ed25519_keymgmt_gen_init),
    { 0, NULL }
};

/* ── SIGNATURE dispatch table ────────────────────────────────────────── */

static const OSSL_DISPATCH vault_sig_funcs[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,              (void(*)(void))vault_sig_newctx              },
    { OSSL_FUNC_SIGNATURE_FREECTX,             (void(*)(void))vault_sig_freectx             },
    { OSSL_FUNC_SIGNATURE_DUPCTX,              (void(*)(void))vault_sig_dupctx              },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,           (void(*)(void))vault_sig_sign_init           },
    { OSSL_FUNC_SIGNATURE_SIGN,                (void(*)(void))vault_sig_sign                },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,    (void(*)(void))vault_sig_digest_sign_init    },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,  (void(*)(void))vault_sig_digest_sign_update  },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,   (void(*)(void))vault_sig_digest_sign_final   },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,         (void(*)(void))vault_sig_verify_init         },
    { OSSL_FUNC_SIGNATURE_VERIFY,              (void(*)(void))vault_sig_verify              },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,      (void(*)(void))vault_sig_set_ctx_params      },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void(*)(void))vault_sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,      (void(*)(void))vault_sig_get_ctx_params      },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void(*)(void))vault_sig_gettable_ctx_params },
    { 0, NULL }
};

/* ── ASYM_CIPHER dispatch table ──────────────────────────────────────── */

static const OSSL_DISPATCH vault_asym_cipher_funcs[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX,              (void(*)(void))vault_asym_cipher_newctx              },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX,             (void(*)(void))vault_asym_cipher_freectx             },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX,              (void(*)(void))vault_asym_cipher_dupctx              },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,        (void(*)(void))vault_asym_cipher_encrypt_init        },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT,             (void(*)(void))vault_asym_cipher_encrypt             },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,        (void(*)(void))vault_asym_cipher_decrypt_init        },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT,             (void(*)(void))vault_asym_cipher_decrypt             },
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,      (void(*)(void))vault_asym_cipher_get_ctx_params      },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void(*)(void))vault_asym_cipher_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,      (void(*)(void))vault_asym_cipher_set_ctx_params      },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void(*)(void))vault_asym_cipher_settable_ctx_params },
    { 0, NULL }
};

/* ── MAC dispatch table ──────────────────────────────────────────────── */

static const OSSL_DISPATCH vault_mac_funcs[] = {
    { OSSL_FUNC_MAC_NEWCTX,              (void(*)(void))vault_mac_newctx              },
    { OSSL_FUNC_MAC_FREECTX,             (void(*)(void))vault_mac_freectx             },
    { OSSL_FUNC_MAC_DUPCTX,              (void(*)(void))vault_mac_dupctx              },
#ifdef OSSL_FUNC_MAC_INIT_SKEY
    { OSSL_FUNC_MAC_INIT_SKEY,           (void(*)(void))vault_mac_init_skey           },
#endif
    { OSSL_FUNC_MAC_UPDATE,              (void(*)(void))vault_mac_update              },
    { OSSL_FUNC_MAC_FINAL,               (void(*)(void))vault_mac_final               },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,      (void(*)(void))vault_mac_get_ctx_params      },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void(*)(void))vault_mac_gettable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (void(*)(void))vault_mac_set_ctx_params      },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void(*)(void))vault_mac_settable_ctx_params },
    { 0, NULL }
};

/* ── algorithm tables ────────────────────────────────────────────────── */

static const OSSL_ALGORITHM vault_keymgmt_algs[] = {
    { "RSA:rsaEncryption", NULL, vault_rsa_keymgmt_funcs,
      "Vault-backed RSA key" },
    { "EC:id-ecPublicKey", NULL, vault_ec_keymgmt_funcs,
      "Vault-backed EC key" },
    { "ED25519",           NULL, vault_ed25519_keymgmt_funcs,
      "Vault-backed Ed25519 key" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM vault_sig_algs[] = {
    { "RSA:rsaEncryption", NULL, vault_sig_funcs,
      "Vault RSA signature" },
    { "ECDSA",             NULL, vault_sig_funcs,
      "Vault ECDSA signature" },
    { "ED25519",           NULL, vault_sig_funcs,
      "Vault Ed25519 signature" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM vault_asym_cipher_algs[] = {
    { "RSA:rsaEncryption", NULL, vault_asym_cipher_funcs,
      "Vault RSA-OAEP encrypt/decrypt" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM vault_mac_algs[] = {
    { "HMAC", NULL, vault_mac_funcs,
      "Vault HMAC" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM vault_store_algs[] = {
    { "vault", "provider=vault", vault_store_funcs,
      "Vault transit key URI loader" },
    { NULL, NULL, NULL, NULL }
};

/* ── query / teardown ────────────────────────────────────────────────── */

static const OSSL_ALGORITHM *vault_query(void *provctx, int op,
                                          int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    switch (op) {
    case OSSL_OP_KEYMGMT:      return vault_keymgmt_algs;
    case OSSL_OP_SIGNATURE:    return vault_sig_algs;
    case OSSL_OP_ASYM_CIPHER:  return vault_asym_cipher_algs;
    case OSSL_OP_MAC:          return vault_mac_algs;
    case OSSL_OP_STORE:        return vault_store_algs;
    default:                   return NULL;
    }
}

static void vault_teardown(void *provctx)
{
    vault_provctx_t *ctx = (vault_provctx_t *)provctx;
    if (!ctx) return;
    vault_ctx_free(ctx->vault);
    OSSL_LIB_CTX_free(ctx->libctx);
    free(ctx);
}

static const OSSL_PARAM vault_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *vault_gettable_params(void *provctx)
{
    (void)provctx;
    return vault_param_types;
}

static int vault_get_params(void *provctx, OSSL_PARAM params[])
{
    (void)provctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Vault Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "0.1.0"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Vault Provider 0.1.0"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,       (void (*)(void))vault_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,(void (*)(void))vault_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,     (void (*)(void))vault_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,(void (*)(void))vault_query    },
    { 0, NULL }
};

/* ── init ────────────────────────────────────────────────────────────── */

#define VAULT_CONF_ADDR      "vault_addr"
#define VAULT_CONF_TOKEN     "vault_token"
#define VAULT_CONF_NAMESPACE "vault_namespace"

typedef OSSL_FUNC_core_get_params_fn *core_get_params_fn;

__attribute__((visibility("default")))
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                        const OSSL_DISPATCH    *in,
                        const OSSL_DISPATCH   **out,
                        void                  **provctx)
{
    core_get_params_fn core_get_params = NULL;
    for (const OSSL_DISPATCH *fn = in; fn->function_id != 0; fn++) {
        if (fn->function_id == OSSL_FUNC_CORE_GET_PARAMS)
            core_get_params = OSSL_FUNC_core_get_params(fn);
    }

    /*
     * Use UTF8_PTR type: OSSL_PROVIDER_get_conf_parameters calls
     * OSSL_PARAM_set_utf8_ptr(), which fails silently on UTF8_STRING params.
     */
    char *addr  = NULL;
    char *token = NULL;
    char *ns    = NULL;

    OSSL_PARAM conf_params[] = {
        OSSL_PARAM_construct_utf8_ptr(VAULT_CONF_ADDR,      &addr,  0),
        OSSL_PARAM_construct_utf8_ptr(VAULT_CONF_TOKEN,     &token, 0),
        OSSL_PARAM_construct_utf8_ptr(VAULT_CONF_NAMESPACE, &ns,    0),
        OSSL_PARAM_construct_end()
    };

    if (core_get_params)
        core_get_params(handle, conf_params);


    vault_provctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return 0;

    ctx->handle = handle;
    ctx->libctx = OSSL_LIB_CTX_new();
    if (!ctx->libctx) { free(ctx); return 0; }

    if (addr && addr[0] && token && token[0])
        ctx->vault = vault_ctx_new(addr, token, (ns && ns[0]) ? ns : NULL);

    *out     = provider_functions;
    *provctx = ctx;
    return 1;
}
