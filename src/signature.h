#ifndef VAULT_SIGNATURE_H
#define VAULT_SIGNATURE_H

#include <stddef.h>
#include <openssl/core_dispatch.h>

/*
 * Dispatch functions for the SIGNATURE operation group.
 * One set covers RSA (PSS and PKCS1v15), another covers ECDSA, another
 * Ed25519.  The provider registers each under its own algorithm name.
 * The void * ctx pointer is always a vault_sigctx_t *.
 */

void *vault_sig_newctx(void *provctx, const char *propq);
void  vault_sig_freectx(void *ctx);
void *vault_sig_dupctx(void *ctx);

int vault_sig_sign_init(void *ctx, void *provkey,
                         const OSSL_PARAM params[]);
int vault_sig_sign(void *ctx,
                   unsigned char *sig, size_t *siglen, size_t sigsize,
                   const unsigned char *tbs, size_t tbslen);

int vault_sig_verify_init(void *ctx, void *provkey,
                           const OSSL_PARAM params[]);
int vault_sig_verify(void *ctx,
                     const unsigned char *sig, size_t siglen,
                     const unsigned char *tbs, size_t tbslen);

int vault_sig_digest_sign_init(void *ctx, const char *mdname, void *provkey,
                               const OSSL_PARAM params[]);
int vault_sig_digest_sign_update(void *ctx, const unsigned char *data,
                                 size_t datalen);
int vault_sig_digest_sign_final(void *ctx,
                                unsigned char *sig, size_t *siglen,
                                size_t sigsize);

/* Params: "digest", "digest-size", "pad-mode" (RSA), "salt-length" (PSS). */
int               vault_sig_set_ctx_params(void *ctx,
                                            const OSSL_PARAM params[]);
const OSSL_PARAM *vault_sig_settable_ctx_params(void *ctx, void *provctx);
int               vault_sig_get_ctx_params(void *ctx, OSSL_PARAM params[]);
const OSSL_PARAM *vault_sig_gettable_ctx_params(void *ctx, void *provctx);

#endif /* VAULT_SIGNATURE_H */
