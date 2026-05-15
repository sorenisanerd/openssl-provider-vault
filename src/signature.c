#include "signature.h"
#include "provider.h"
#include "vault_client.h"
#include "vault_keyref.h"
#include "vault_format.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

typedef struct {
    vault_provctx_t *provctx;
    vault_keyref_t  *key;        /* borrowed — not owned */
    EVP_MD_CTX      *mdctx;      /* used by digest-sign / digest-verify */

    /* Algorithm parameters set during *_init(). */
    int              hash_nid;   /* NID_sha256, etc.                  */
    char             sig_alg[32];/* "pss", "pkcs1v15", "ecdsa", "ed"  */
} vault_sigctx_t;

void *vault_sig_newctx(void *provctx, const char *propq)
{
    (void)propq;
    vault_sigctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->provctx  = (vault_provctx_t *)provctx;
    ctx->hash_nid = NID_sha256;                  /* default digest */
    strncpy(ctx->sig_alg, "pss", sizeof(ctx->sig_alg) - 1);
    return ctx;
}

void vault_sig_freectx(void *ctx)
{
    vault_sigctx_t *sctx = (vault_sigctx_t *)ctx;
    if (!sctx)
        return;
    EVP_MD_CTX_free(sctx->mdctx);
    free(sctx);
}

void *vault_sig_dupctx(void *ctx)
{
    vault_sigctx_t *src = (vault_sigctx_t *)ctx;
    vault_sigctx_t *dst = malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    dst->mdctx = NULL;
    if (src->mdctx) {
        dst->mdctx = EVP_MD_CTX_new();
        if (!dst->mdctx) {
            free(dst);
            return NULL;
        }
        if (!EVP_MD_CTX_copy_ex(dst->mdctx, src->mdctx)) {
            EVP_MD_CTX_free(dst->mdctx);
            free(dst);
            return NULL;
        }
    }
    return dst;
}

static int apply_params(vault_sigctx_t *ctx, const OSSL_PARAM params[])
{
    if (!params)
        return 1;

    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        char digest_name[64] = {0};
        char *dn = digest_name;
        if (!OSSL_PARAM_get_utf8_string(p, &dn, sizeof(digest_name)))
            return 0;
        int nid = OBJ_txt2nid(digest_name);
        if (nid == NID_undef)
            return 0;
        ctx->hash_nid = nid;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p) {
        char mode[32] = {0};
        char *mp = mode;
        if (!OSSL_PARAM_get_utf8_string(p, &mp, sizeof(mode)))
            return 0;
        strncpy(ctx->sig_alg, mode, sizeof(ctx->sig_alg) - 1);
    }

    return 1;
}

int vault_sig_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    vault_sigctx_t *sctx = (vault_sigctx_t *)ctx;
    sctx->key = (vault_keyref_t *)provkey;
    return apply_params(sctx, params);
}

int vault_sig_sign(void *ctx,
                   unsigned char *sig, size_t *siglen, size_t sigsize,
                   const unsigned char *tbs, size_t tbslen)
{
    vault_sigctx_t *sctx = (vault_sigctx_t *)ctx;

    const char *hash_alg = vault_hash_alg_name(sctx->hash_nid);
    if (!hash_alg)
        return 0;

    unsigned char *vault_sig = NULL;
    size_t         vault_sig_len = 0;

    if (vault_sign(sctx->provctx->vault,
                   sctx->key->key_name,
                   sctx->key->key_version,
                   hash_alg,
                   sctx->sig_alg,
                   tbs, tbslen,
                   &vault_sig, &vault_sig_len) != 0)
        return 0;

    /* Size query. */
    if (!sig) {
        *siglen = vault_sig_len;
        free(vault_sig);
        return 1;
    }

    if (vault_sig_len > sigsize) {
        free(vault_sig);
        return 0;
    }

    memcpy(sig, vault_sig, vault_sig_len);
    *siglen = vault_sig_len;
    free(vault_sig);
    return 1;
}

int vault_sig_verify_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    vault_sigctx_t *sctx = (vault_sigctx_t *)ctx;
    sctx->key = (vault_keyref_t *)provkey;
    return apply_params(sctx, params);
}

int vault_sig_verify(void *ctx,
                     const unsigned char *sig, size_t siglen,
                     const unsigned char *tbs, size_t tbslen)
{
    vault_sigctx_t *sctx = (vault_sigctx_t *)ctx;

    const char *hash_alg = vault_hash_alg_name(sctx->hash_nid);
    if (!hash_alg)
        return 0;

    int valid = 0;
    if (vault_verify(sctx->provctx->vault,
                     sctx->key->key_name,
                     sctx->key->key_version,
                     hash_alg,
                     sctx->sig_alg,
                     tbs, tbslen,
                     sig, siglen,
                     &valid) != 0)
        return 0;

    return valid;
}

int vault_sig_digest_sign_init(void *ctx, const char *mdname, void *provkey,
                               const OSSL_PARAM params[])
{
    vault_sigctx_t *sctx = (vault_sigctx_t *)ctx;
    if (!sctx || !mdname)
        return 0;

    sctx->key = (vault_keyref_t *)provkey;
    int pad_mode_was_set = OSSL_PARAM_locate_const(params,
                                                   OSSL_SIGNATURE_PARAM_PAD_MODE) != NULL;
    if (!apply_params(sctx, params))
        return 0;

    if (!pad_mode_was_set && sctx->key && sctx->key->key_type
        && strncmp(sctx->key->key_type, "rsa", 3) == 0) {
        strncpy(sctx->sig_alg, "pkcs1v15", sizeof(sctx->sig_alg) - 1);
        sctx->sig_alg[sizeof(sctx->sig_alg) - 1] = '\0';
    }

    int nid = OBJ_txt2nid(mdname);
    if (nid == NID_undef)
        return 0;

    const EVP_MD *md = EVP_get_digestbyname(mdname);
    if (!md)
        return 0;

    EVP_MD_CTX_free(sctx->mdctx);
    sctx->mdctx = EVP_MD_CTX_new();
    if (!sctx->mdctx)
        return 0;

    sctx->hash_nid = nid;
    if (!EVP_DigestInit_ex(sctx->mdctx, md, NULL)) {
        EVP_MD_CTX_free(sctx->mdctx);
        sctx->mdctx = NULL;
        return 0;
    }

    return 1;
}

int vault_sig_digest_sign_update(void *ctx, const unsigned char *data,
                                 size_t datalen)
{
    vault_sigctx_t *sctx = (vault_sigctx_t *)ctx;
    if (!sctx || !sctx->mdctx)
        return 0;
    return EVP_DigestUpdate(sctx->mdctx, data, datalen);
}

int vault_sig_digest_sign_final(void *ctx,
                                unsigned char *sig, size_t *siglen,
                                size_t sigsize)
{
    vault_sigctx_t *sctx = (vault_sigctx_t *)ctx;
    if (!sctx || !sctx->mdctx || !siglen)
        return 0;

    EVP_MD_CTX *tmp = EVP_MD_CTX_new();
    if (!tmp)
        return 0;
    if (!EVP_MD_CTX_copy_ex(tmp, sctx->mdctx)) {
        EVP_MD_CTX_free(tmp);
        return 0;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    int ok = EVP_DigestFinal_ex(tmp, digest, &digest_len);
    EVP_MD_CTX_free(tmp);
    if (!ok)
        return 0;

    return vault_sig_sign(ctx, sig, siglen, sigsize, digest, digest_len);
}

/* ── params ───────────────────────────────────────────────────────────── */

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM *vault_sig_settable_ctx_params(void *ctx, void *provctx)
{
    (void)ctx;
    (void)provctx;
    return settable_ctx_params;
}

int vault_sig_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    return apply_params((vault_sigctx_t *)ctx, params);
}

static const OSSL_PARAM gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM *vault_sig_gettable_ctx_params(void *ctx, void *provctx)
{
    (void)ctx;
    (void)provctx;
    return gettable_ctx_params;
}

static int set_algorithm_id_param(vault_sigctx_t *sctx, OSSL_PARAM *p)
{
    if (!sctx->key || !sctx->key->key_type)
        return OSSL_PARAM_set_octet_string(p, NULL, 0);

    int pkey_nid = NID_undef;
    int paramtype = V_ASN1_UNDEF;

    if (strncmp(sctx->key->key_type, "rsa", 3) == 0) {
        if (strcmp(sctx->sig_alg, "pkcs1v15") != 0)
            return OSSL_PARAM_set_octet_string(p, NULL, 0);
        pkey_nid = NID_rsaEncryption;
        paramtype = V_ASN1_NULL;
    } else if (strncmp(sctx->key->key_type, "ecdsa", 5) == 0) {
        pkey_nid = NID_X9_62_id_ecPublicKey;
    } else {
        return OSSL_PARAM_set_octet_string(p, NULL, 0);
    }

    int sign_nid = NID_undef;
    if (!OBJ_find_sigid_by_algs(&sign_nid, sctx->hash_nid, pkey_nid))
        return OSSL_PARAM_set_octet_string(p, NULL, 0);

    X509_ALGOR *alg = X509_ALGOR_new();
    if (!alg)
        return 0;

    int ok = 0;
    unsigned char *der = NULL;
    int der_len = 0;

    if (!X509_ALGOR_set0(alg, OBJ_nid2obj(sign_nid), paramtype, NULL))
        goto done;

    der_len = i2d_X509_ALGOR(alg, &der);
    if (der_len <= 0)
        goto done;

    ok = OSSL_PARAM_set_octet_string(p, der, (size_t)der_len);

done:
    OPENSSL_free(der);
    X509_ALGOR_free(alg);
    return ok;
}

int vault_sig_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    vault_sigctx_t *sctx = (vault_sigctx_t *)ctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p) {
        const char *name = OBJ_nid2sn(sctx->hash_nid);
        if (!OSSL_PARAM_set_utf8_string(p, name ? name : ""))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p) {
        if (!OSSL_PARAM_set_utf8_string(p, sctx->sig_alg))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        if (!set_algorithm_id_param(sctx, p))
            return 0;
    }

    return 1;
}
