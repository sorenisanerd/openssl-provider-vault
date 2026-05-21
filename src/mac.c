#include "mac.h"
#include "provider.h"
#include "vault_client.h"
#include "vault_keyref.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>

typedef struct {
    vault_provctx_t *provctx;
    vault_keyref_t  *key;          /* borrowed — not owned */
    char             hash_alg[32]; /* Vault algorithm name, e.g. "sha2-256" */
    unsigned char   *data_buf;     /* accumulated update data */
    size_t           data_len;
} vault_mac_ctx_t;

static const char *mac_vault_hash_alg(const char *digest_name)
{
    int nid = OBJ_txt2nid(digest_name);
    switch (nid) {
    case NID_sha256: return "sha2-256";
    case NID_sha384: return "sha2-384";
    case NID_sha512: return "sha2-512";
    default:         return NULL;
    }
}

void *vault_mac_newctx(void *provctx)
{
    vault_mac_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->provctx = (vault_provctx_t *)provctx;
    strncpy(ctx->hash_alg, "sha2-256", sizeof(ctx->hash_alg) - 1);
    return ctx;
}

void vault_mac_freectx(void *ctx)
{
    vault_mac_ctx_t *mctx = (vault_mac_ctx_t *)ctx;
    if (!mctx)
        return;
    free(mctx->data_buf);
    free(mctx);
}

void *vault_mac_dupctx(void *ctx)
{
    vault_mac_ctx_t *src = (vault_mac_ctx_t *)ctx;
    vault_mac_ctx_t *dst = malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    dst->data_buf = NULL;
    dst->data_len = 0;
    if (src->data_buf && src->data_len > 0) {
        dst->data_buf = malloc(src->data_len);
        if (!dst->data_buf) {
            free(dst);
            return NULL;
        }
        memcpy(dst->data_buf, src->data_buf, src->data_len);
        dst->data_len = src->data_len;
    }
    return dst;
}

static int apply_params(vault_mac_ctx_t *ctx, const OSSL_PARAM params[])
{
    if (!params)
        return 1;

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (p) {
        char digest_name[64] = {0};
        char *dn = digest_name;
        if (!OSSL_PARAM_get_utf8_string(p, &dn, sizeof(digest_name)))
            return 0;
        const char *vault_alg = mac_vault_hash_alg(digest_name);
        if (!vault_alg)
            return 0;
        strncpy(ctx->hash_alg, vault_alg, sizeof(ctx->hash_alg) - 1);
        ctx->hash_alg[sizeof(ctx->hash_alg) - 1] = '\0';
    }
    return 1;
}

/*
 * vault_mac_init_skey — initialize with a provider-side key object.
 * The 'key' pointer here is a vault_keyref_t * (not raw bytes),
 * passed through OSSL_FUNC_MAC_INIT_SKEY (OpenSSL 3.5+).
 */
int vault_mac_init_skey(void *ctx, const void *key,
                        const OSSL_PARAM params[])
{
    vault_mac_ctx_t *mctx = (vault_mac_ctx_t *)ctx;
    mctx->key = (vault_keyref_t *)key;
    free(mctx->data_buf);
    mctx->data_buf = NULL;
    mctx->data_len = 0;
    return apply_params(mctx, params);
}

int vault_mac_update(void *ctx, const unsigned char *in, size_t inlen)
{
    vault_mac_ctx_t *mctx = (vault_mac_ctx_t *)ctx;
    size_t new_len = mctx->data_len + inlen;
    unsigned char *tmp = malloc(new_len);
    if (!tmp)
        return 0;
    if (mctx->data_buf) {
        memcpy(tmp, mctx->data_buf, mctx->data_len);
        free(mctx->data_buf);
    }
    memcpy(tmp + mctx->data_len, in, inlen);
    mctx->data_buf = tmp;
    mctx->data_len = new_len;
    return 1;
}

int vault_mac_final(void *ctx, unsigned char *out, size_t *outlen,
                    size_t outsize)
{
    vault_mac_ctx_t *mctx = (vault_mac_ctx_t *)ctx;

    if (!out) {
        *outlen = 64;
        return 1;
    }

    unsigned char *hmac = NULL;
    size_t         hmac_len = 0;

    if (vault_hmac(mctx->provctx->vault,
                   mctx->key->key_name,
                   mctx->key->key_version,
                   mctx->hash_alg,
                   mctx->data_buf,
                   mctx->data_len,
                   &hmac, &hmac_len) != 0)
        return 0;

    if (hmac_len > outsize) {
        free(hmac);
        return 0;
    }

    memcpy(out, hmac, hmac_len);
    *outlen = hmac_len;
    free(hmac);
    return 1;
}

static const OSSL_PARAM gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM *vault_mac_gettable_ctx_params(void *ctx, void *provctx)
{
    (void)ctx; (void)provctx;
    return gettable_ctx_params;
}

int vault_mac_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    vault_mac_ctx_t *mctx = (vault_mac_ctx_t *)ctx;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_DIGEST);
    if (p) {
        if (!OSSL_PARAM_set_utf8_string(p, mctx->hash_alg))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM *vault_mac_settable_ctx_params(void *ctx, void *provctx)
{
    (void)ctx; (void)provctx;
    return settable_ctx_params;
}

int vault_mac_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    return apply_params((vault_mac_ctx_t *)ctx, params);
}
