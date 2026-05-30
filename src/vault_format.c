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

#include "vault_format.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/obj_mac.h>

char *vault_request_encode(const unsigned char *data, size_t len)
{
    if (!data || len == 0)
        return NULL;

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    if (!b64 || !mem) {
        BIO_free(b64);
        BIO_free(mem);
        return NULL;
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);

    BUF_MEM *bm;
    BIO_get_mem_ptr(mem, &bm);

    char *out = malloc(bm->length + 1);
    if (out) {
        memcpy(out, bm->data, bm->length);
        out[bm->length] = '\0';
    }

    BIO_free_all(b64);
    return out;
}

int vault_response_decode(const char *vault_str,
                           unsigned char **out, size_t *out_len)
{
    static const char prefix[] = "vault:v1:";
    static const size_t prefix_len = sizeof(prefix) - 1;

    if (!vault_str || strncmp(vault_str, prefix, prefix_len) != 0)
        return -1;

    const char *b64 = vault_str + prefix_len;
    size_t b64_len  = strlen(b64);

    BIO *b64bio = BIO_new(BIO_f_base64());
    BIO *mem    = BIO_new_mem_buf(b64, (int)b64_len);
    if (!b64bio || !mem) {
        BIO_free(b64bio);
        BIO_free(mem);
        return -1;
    }

    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64bio, mem);

    /* Decoded length is at most 3/4 of the base64 input. */
    size_t max_out = ((b64_len + 3) / 4) * 3;
    *out = malloc(max_out);
    if (!*out) {
        BIO_free_all(b64bio);
        return -1;
    }

    int n = BIO_read(b64bio, *out, (int)max_out);
    BIO_free_all(b64bio);

    if (n <= 0) {
        free(*out);
        *out = NULL;
        return -1;
    }

    *out_len = (size_t)n;
    return 0;
}

char *vault_response_encode(const unsigned char *data, size_t len)
{
    char *b64 = vault_request_encode(data, len);
    if (!b64) return NULL;
    char *out;
    if (asprintf(&out, "vault:v1:%s", b64) < 0)
        out = NULL;
    free(b64);
    return out;
}

int vault_base64_decode(const char *b64, unsigned char **out, size_t *out_len)
{
    if (!b64 || !out || !out_len)
        return -1;

    size_t b64_len = strlen(b64);

    BIO *b64bio = BIO_new(BIO_f_base64());
    BIO *mem    = BIO_new_mem_buf(b64, (int)b64_len);
    if (!b64bio || !mem) {
        BIO_free(b64bio);
        BIO_free(mem);
        return -1;
    }

    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64bio, mem);

    size_t max_out = ((b64_len + 3) / 4) * 3;
    *out = malloc(max_out);
    if (!*out) {
        BIO_free_all(b64bio);
        return -1;
    }

    int n = BIO_read(b64bio, *out, (int)max_out);
    BIO_free_all(b64bio);

    if (n <= 0) {
        free(*out);
        *out = NULL;
        return -1;
    }

    *out_len = (size_t)n;
    return 0;
}

const char *vault_hash_alg_name(int hash_nid)
{
    switch (hash_nid) {
    case NID_sha1:       return "sha1";
    case NID_sha224:     return "sha2-224";
    case NID_sha256:     return "sha2-256";
    case NID_sha384:     return "sha2-384";
    case NID_sha512:     return "sha2-512";
    case NID_sha3_224:   return "sha3-224";
    case NID_sha3_256:   return "sha3-256";
    case NID_sha3_384:   return "sha3-384";
    case NID_sha3_512:   return "sha3-512";
    default:             return NULL;
    }
}

const char *vault_key_type_name(int pkey_type, int bits, int curve_nid)
{
    switch (pkey_type) {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA_PSS:
        switch (bits) {
        case 2048: return "rsa-2048";
        case 3072: return "rsa-3072";
        case 4096: return "rsa-4096";
        default:   return NULL;
        }

    case EVP_PKEY_EC:
        switch (curve_nid) {
        case NID_X9_62_prime256v1: return "ecdsa-p256";
        case NID_secp384r1:        return "ecdsa-p384";
        case NID_secp521r1:        return "ecdsa-p521";
        default:                   return NULL;
        }

    case EVP_PKEY_ED25519:
        return "ed25519";

    default:
        return NULL;
    }
}
