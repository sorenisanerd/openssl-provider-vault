#ifndef VAULT_PROVIDER_INT_H
#define VAULT_PROVIDER_INT_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "vault_client.h"

/* Provider context — one per loaded provider instance. */
typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX           *libctx;
    vault_ctx_t            *vault;
} vault_provctx_t;

/* Entry point declared for completeness; defined in provider.c. */
OSSL_provider_init_fn OSSL_provider_init;

#endif /* VAULT_PROVIDER_INT_H */
