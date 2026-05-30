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

#ifndef VAULT_FORMAT_H
#define VAULT_FORMAT_H

#include <stddef.h>

/*
 * vault_request_encode  — base64-encode binary data for a Vault JSON body.
 * Returns a NUL-terminated string; caller must free().
 * Returns NULL on allocation failure.
 */
char *vault_request_encode(const unsigned char *data, size_t len);

/*
 * vault_response_decode  — strip the "vault:v1:" prefix then base64-decode.
 * *out is malloc'd; caller must free().
 * Returns 0 on success, -1 on bad prefix or decode error.
 */
int vault_response_decode(const char     *vault_str,
                           unsigned char **out,
                           size_t         *out_len);

/*
 * vault_response_encode  — inverse of vault_response_decode.
 * Prepends "vault:v1:" and base64-encodes binary data, producing the format
 * Vault expects for signature/hmac fields in verify requests.
 * Returns a NUL-terminated string; caller must free().
 * Returns NULL on allocation failure.
 */
char *vault_response_encode(const unsigned char *data, size_t len);

/*
 * vault_base64_decode  — decode plain base64 (no "vault:v1:" prefix).
 * Used for Vault responses whose values are not vault-prefixed
 * (e.g. plaintext from decrypt, random_bytes from /transit/random).
 * *out is malloc'd; caller must free().
 * Returns 0 on success, -1 on error.
 */
int vault_base64_decode(const char     *b64,
                         unsigned char **out,
                         size_t         *out_len);

/*
 * vault_hash_alg_name  — map an OpenSSL digest NID to the Vault algorithm
 * string used in request bodies (e.g. NID_sha256 → "sha2-256").
 * Returns NULL for unsupported NIDs.  Returned pointer is static storage.
 */
const char *vault_hash_alg_name(int hash_nid);

/*
 * vault_key_type_name  — map an OpenSSL key type + size to the Vault key
 * type string used when creating keys (e.g. EVP_PKEY_RSA + 2048 → "rsa-2048").
 * curve_nid is only consulted for EVP_PKEY_EC.
 * Returns NULL for unsupported combinations.  Returned pointer is static.
 */
const char *vault_key_type_name(int pkey_type, int bits, int curve_nid);

#endif /* VAULT_FORMAT_H */
