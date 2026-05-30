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

#ifndef VAULT_KEYREF_H
#define VAULT_KEYREF_H

#include <stddef.h>

/*
 * vault_keyref_t — the cross-session key handle.
 *
 * Serialised as the opaque "reference" bytes passed to keymgmt_load() and
 * stored in a STORE object.  All heap fields are owned by the struct; free
 * with vault_keyref_free().
 *
 * Wire layout (all lengths big-endian uint32):
 *   [4] name_len  [name_len] name
 *   [4] version
 *   [4] key_type_len  [key_type_len] key_type
 *   [4] pubkey_der_len  [pubkey_der_len] pubkey_der
 */
typedef struct {
    char          *key_name;       /* Vault key name, e.g. "my-rsa-key"   */
    int            key_version;    /* 0 = latest                           */
    char          *key_type;       /* e.g. "rsa-2048", "ecdsa-p256"        */
    unsigned char *pubkey_der;     /* DER SubjectPublicKeyInfo; may be NULL */
    size_t         pubkey_der_len;
} vault_keyref_t;

vault_keyref_t *vault_keyref_new(const char    *key_name,
                                  int            key_version,
                                  const char    *key_type,
                                  const unsigned char *pubkey_der,
                                  size_t         pubkey_der_len);

void vault_keyref_free(vault_keyref_t *ref);

/*
 * Serialise to a flat byte buffer.
 * *out is malloc'd; caller must free().
 * Returns 0 on success, -1 on error.
 */
int vault_keyref_serialize(const vault_keyref_t  *ref,
                            unsigned char        **out,
                            size_t                *out_len);

/*
 * Deserialise from the byte buffer produced by vault_keyref_serialize().
 * Returns a newly allocated vault_keyref_t, or NULL on error.
 */
vault_keyref_t *vault_keyref_deserialize(const unsigned char *data,
                                          size_t               len);

#endif /* VAULT_KEYREF_H */
