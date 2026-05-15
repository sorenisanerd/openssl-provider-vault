#include "provider.h"
#include "vault_client.h"
#include "vault_keyref.h"
#include "vault_store_uri.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/store.h>

/* ── loader context ───────────────────────────────────────────────────── */

typedef struct {
    vault_provctx_t *provctx;
    char            *key_name;
    int              version;    /* from URI ?version=N; 0 = latest */
    int              loaded;     /* set to 1 after serving the key  */
} vault_store_ctx_t;

/* ── vault key type → OpenSSL algorithm name ──────────────────────────── */

static const char *vault_type_to_algo(const char *key_type)
{
    if (!key_type)
        return NULL;
    if (strncmp(key_type, "rsa-", 4) == 0)
        return "RSA";
    if (strncmp(key_type, "ecdsa-", 6) == 0)
        return "EC";
    if (strcmp(key_type, "ed25519") == 0)
        return "ED25519";
    if (strcmp(key_type, "ed448") == 0)
        return "ED448";
    return NULL;
}

/* ── dispatch functions ───────────────────────────────────────────────── */

#include <stdio.h>

static void *vault_store_open(void *provctx, const char *uri)
{
    vault_uri_t parsed = {0};
    if (vault_uri_parse(uri, &parsed) != 0)
        return NULL;

    vault_store_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        vault_uri_free(&parsed);
        return NULL;
    }
    ctx->provctx  = (vault_provctx_t *)provctx;
    ctx->key_name = parsed.key_name;  /* take ownership */
    ctx->version  = parsed.version;
    /* vault_uri_free would free key_name; just zero the struct instead */
    memset(&parsed, 0, sizeof(parsed));
    return ctx;
}

static int vault_store_load(void *loaderctx,
                             OSSL_CALLBACK *object_cb, void *object_cbarg,
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    (void)pw_cb;
    (void)pw_cbarg;

    vault_store_ctx_t *sctx = (vault_store_ctx_t *)loaderctx;
    if (sctx->loaded)
        return 0;

    /*
     * Mark as done immediately so that eof() returns 1 regardless of whether
     * we succeed. This prevents the OSSL_STORE loop from spinning when we
     * encounter an error (no Vault connection, key not found, etc.).
     */
    sctx->loaded = 1;

    if (!sctx->provctx->vault)
        return 0;

    vault_key_info_t info = {0};
    if (vault_get_key(sctx->provctx->vault, sctx->key_name, &info) != 0) {
        return 0;
    }

    int ver = sctx->version ? sctx->version : info.latest_version;
    vault_keyref_t *ref = vault_keyref_new(sctx->key_name, ver,
                                            info.key_type,
                                            info.pubkey_der,
                                            info.pubkey_der_len);
    vault_key_info_free(&info);
    if (!ref)
        return 0;

    unsigned char *ser    = NULL;
    size_t         ser_len = 0;
    if (vault_keyref_serialize(ref, &ser, &ser_len) != 0) {
        vault_keyref_free(ref);
        return 0;
    }

    const char *algo = vault_type_to_algo(ref->key_type);
    vault_keyref_free(ref);
    if (!algo) {
        free(ser);
        return 0;
    }

    int obj_type = OSSL_OBJECT_PKEY;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE,
                                 &obj_type),
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                         (char *)algo, 0),
        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                          ser, ser_len),
        OSSL_PARAM_construct_end()
    };

    int rv = object_cb(params, object_cbarg);
    free(ser);
    return rv;
}

static int vault_store_eof(void *loaderctx)
{
    return ((vault_store_ctx_t *)loaderctx)->loaded;
}

static int vault_store_close(void *loaderctx)
{
    vault_store_ctx_t *sctx = (vault_store_ctx_t *)loaderctx;
    if (!sctx)
        return 1;
    free(sctx->key_name);
    free(sctx);
    return 1;
}

/* ── dispatch table ───────────────────────────────────────────────────── */

const OSSL_DISPATCH vault_store_funcs[] = {
    { OSSL_FUNC_STORE_OPEN,  (void (*)(void))vault_store_open  },
    { OSSL_FUNC_STORE_LOAD,  (void (*)(void))vault_store_load  },
    { OSSL_FUNC_STORE_EOF,   (void (*)(void))vault_store_eof   },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))vault_store_close },
    { 0, NULL }
};
