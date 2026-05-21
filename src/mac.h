#ifndef VAULT_MAC_H
#define VAULT_MAC_H

#include <stddef.h>
#include <openssl/core_dispatch.h>

void *vault_mac_newctx(void *provctx);
void  vault_mac_freectx(void *ctx);
void *vault_mac_dupctx(void *ctx);

#ifdef OSSL_FUNC_MAC_INIT_SKEY
int vault_mac_init_skey(void *ctx, const void *key,
                        const OSSL_PARAM params[]);
#endif
int vault_mac_update(void *ctx, const unsigned char *in, size_t inlen);
int vault_mac_final(void *ctx, unsigned char *out, size_t *outlen,
                    size_t outsize);

int               vault_mac_get_ctx_params(void *ctx, OSSL_PARAM params[]);
const OSSL_PARAM *vault_mac_gettable_ctx_params(void *ctx, void *provctx);
int               vault_mac_set_ctx_params(void *ctx,
                                            const OSSL_PARAM params[]);
const OSSL_PARAM *vault_mac_settable_ctx_params(void *ctx, void *provctx);

#endif /* VAULT_MAC_H */
