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

#ifndef VAULT_CLIENT_H
#define VAULT_CLIENT_H

#include <stddef.h>

/*
 * Opaque Vault HTTP client context.  One instance is held in the provider
 * context and shared across all operations.  All vault_* functions below are
 * the mock seam: tests compile against mock_vault_client.c instead of
 * vault_client.c and never touch the network.
 */
typedef struct vault_ctx vault_ctx_t;

vault_ctx_t *vault_ctx_new(const char *addr,
                            const char *token,
                            const char *ns);     /* ns may be NULL */
void         vault_ctx_free(vault_ctx_t *ctx);

/*
 * Key metadata returned by vault_get_key().
 * Caller owns all heap fields; free with vault_key_info_free().
 */
typedef struct {
    char          *key_type;        /* e.g. "rsa-2048", "ecdsa-p256" */
    int            latest_version;
    int            min_decrypt_version;
    unsigned char *pubkey_der;      /* DER-encoded SubjectPublicKeyInfo */
    size_t         pubkey_der_len;
} vault_key_info_t;

int  vault_get_key(vault_ctx_t *ctx,
                   const char *key_name,
                   vault_key_info_t *info_out);

void vault_key_info_free(vault_key_info_t *info);

/*
 * Create a new key in Vault.
 *   key_type: "rsa-2048", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521",
 *             "ed25519", "aes256-gcm96", "hmac", etc.
 *   exportable: non-zero to allow future private-key export.
 */
int vault_create_key(vault_ctx_t *ctx,
                     const char *key_name,
                     const char *key_type,
                     int exportable);

/*
 * Sign pre-hashed data.
 *   hash_alg:  "sha2-256", "sha2-384", "sha2-512", "sha3-256", …
 *   sig_alg:   "pss" | "pkcs1v15"  (RSA only; ignored for EC/Ed)
 *   key_version: 0 = latest
 *   input is the raw digest bytes (prehashed=true is always sent).
 *   *sig_out is malloc'd by callee; caller must free().
 */
int vault_sign(vault_ctx_t    *ctx,
               const char     *key_name,
               int             key_version,
               const char     *hash_alg,
               const char     *sig_alg,
               const unsigned char *input,
               size_t          input_len,
               unsigned char **sig_out,
               size_t         *sig_out_len);

/*
 * Verify a signature over pre-hashed data.
 *   *valid_out is set to 1 if the signature is valid, 0 otherwise.
 */
int vault_verify(vault_ctx_t         *ctx,
                 const char          *key_name,
                 int                  key_version,
                 const char          *hash_alg,
                 const char          *sig_alg,
                 const unsigned char *input,
                 size_t               input_len,
                 const unsigned char *sig,
                 size_t               sig_len,
                 int                 *valid_out);

/*
 * RSA-OAEP asymmetric encrypt / decrypt.
 * *out is malloc'd by callee; caller must free().
 */
int vault_asym_encrypt(vault_ctx_t         *ctx,
                       const char          *key_name,
                       int                  key_version,
                       const unsigned char *plaintext,
                       size_t               plaintext_len,
                       unsigned char      **ciphertext_out,
                       size_t              *ciphertext_out_len);

int vault_asym_decrypt(vault_ctx_t         *ctx,
                       const char          *key_name,
                       int                  key_version,
                       const unsigned char *ciphertext,
                       size_t               ciphertext_len,
                       unsigned char      **plaintext_out,
                       size_t              *plaintext_out_len);

/*
 * Symmetric (AES-GCM / ChaCha20-Poly1305) encrypt / decrypt.
 * *out is malloc'd by callee; caller must free().
 */
int vault_sym_encrypt(vault_ctx_t         *ctx,
                      const char          *key_name,
                      int                  key_version,
                      const unsigned char *plaintext,
                      size_t               plaintext_len,
                      unsigned char      **ciphertext_out,
                      size_t              *ciphertext_out_len);

int vault_sym_decrypt(vault_ctx_t         *ctx,
                      const char          *key_name,
                      int                  key_version,
                      const unsigned char *ciphertext,
                      size_t               ciphertext_len,
                      unsigned char      **plaintext_out,
                      size_t              *plaintext_out_len);

/*
 * HMAC.  algorithm: "sha2-256", "sha2-384", "sha2-512", "sha3-256", …
 * *hmac_out is malloc'd by callee; caller must free().
 */
int vault_hmac(vault_ctx_t         *ctx,
               const char          *key_name,
               int                  key_version,
               const char          *algorithm,
               const unsigned char *input,
               size_t               input_len,
               unsigned char      **hmac_out,
               size_t              *hmac_out_len);

/*
 * Hash (delegates to /transit/hash).
 * *hash_out is malloc'd by callee; caller must free().
 */
int vault_hash(vault_ctx_t         *ctx,
               const char          *algorithm,
               const unsigned char *input,
               size_t               input_len,
               unsigned char      **hash_out,
               size_t              *hash_out_len);

/*
 * Random bytes from /transit/random/:bytes.
 * *random_out is malloc'd (bytes long) by callee; caller must free().
 */
int vault_random(vault_ctx_t    *ctx,
                 size_t          bytes,
                 unsigned char **random_out);

#endif /* VAULT_CLIENT_H */
