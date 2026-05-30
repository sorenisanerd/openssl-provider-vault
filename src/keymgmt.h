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

#ifndef VAULT_KEYMGMT_H
#define VAULT_KEYMGMT_H

#include <stddef.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

/*
 * Dispatch functions for the KEYMGMT operation group.
 * All are registered in the provider dispatch table for each key type
 * (RSA, EC, ED25519).  The void * keydata pointer is always a
 * vault_keyref_t *.
 */

/* keymgmt_gen sub-context — holds parameters until gen() is called. */
typedef struct vault_keymgmt_genctx vault_keymgmt_genctx_t;

void *vault_keymgmt_new(void *provctx);
void  vault_keymgmt_free(void *keydata);
int   vault_keymgmt_has(const void *keydata, int selection);

/* Load a key from a serialised vault_keyref_t (cross-session reference). */
void *vault_keymgmt_load(const void *reference, size_t reference_sz);

/* Export public key material as OSSL_PARAMs (no private key ever). */
int   vault_keymgmt_export(void *keydata, int selection,
                            OSSL_CALLBACK *param_cb, void *cbarg);

/* Import: only public key material accepted; no raw private key import. */
int vault_keymgmt_import(void *keydata, int selection,
                          const OSSL_PARAM params[]);
const OSSL_PARAM *vault_keymgmt_import_types(int selection);
const OSSL_PARAM *vault_keymgmt_export_types(int selection);
const char *vault_keymgmt_query_operation_name(int operation_id);

/* Gettable/settable param descriptors. */
const OSSL_PARAM *vault_keymgmt_gettable_params(void *provctx);
int               vault_keymgmt_get_params(void *keydata,
                                            OSSL_PARAM params[]);

/* Gen lifecycle: init → gen → cleanup. */
void *vault_keymgmt_gen_init(void *provctx, int selection,
                              const OSSL_PARAM params[]);

/* Per-type gen_init wrappers that set pkey_type and default key sizes. */
void *vault_rsa_keymgmt_gen_init(void *provctx, int selection,
                                   const OSSL_PARAM params[]);
void *vault_ec_keymgmt_gen_init(void *provctx, int selection,
                                  const OSSL_PARAM params[]);
void *vault_ed25519_keymgmt_gen_init(void *provctx, int selection,
                                      const OSSL_PARAM params[]);
int   vault_keymgmt_gen_set_params(void *genctx,
                                    const OSSL_PARAM params[]);
const OSSL_PARAM *vault_keymgmt_gen_settable_params(void *genctx,
                                                      void *provctx);
void *vault_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg);
void  vault_keymgmt_gen_cleanup(void *genctx);

#endif /* VAULT_KEYMGMT_H */
