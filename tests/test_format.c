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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/obj_mac.h>
#include <openssl/evp.h>

#include "vault_format.h"
#include "wrap_malloc.h"

/* ── vault_request_encode ────────────────────────────────────────────── */

static void test_encode_hello(void **state)
{
    (void)state;
    const unsigned char in[] = "Hello";
    char *enc = vault_request_encode(in, 5);
    assert_non_null(enc);
    assert_string_equal(enc, "SGVsbG8=");
    free(enc);
}

static void test_encode_roundtrip(void **state)
{
    (void)state;
    /* 32 bytes of arbitrary data — exercises multi-block base64. */
    const unsigned char in[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    };
    char *enc = vault_request_encode(in, sizeof(in));
    assert_non_null(enc);

    /* Prepend the vault prefix and round-trip through decode. */
    char vault_str[128];
    snprintf(vault_str, sizeof(vault_str), "vault:v1:%s", enc);
    free(enc);

    unsigned char *out = NULL;
    size_t out_len = 0;
    assert_int_equal(0, vault_response_decode(vault_str, &out, &out_len));
    assert_int_equal(sizeof(in), out_len);
    assert_memory_equal(in, out, sizeof(in));
    free(out);
}

static void test_encode_null_data(void **state)
{
    (void)state;
    assert_null(vault_request_encode(NULL, 0));
}

/* ── vault_response_decode ───────────────────────────────────────────── */

static void test_decode_hello(void **state)
{
    (void)state;
    unsigned char *out = NULL;
    size_t out_len = 0;
    assert_int_equal(0, vault_response_decode("vault:v1:SGVsbG8=",
                                               &out, &out_len));
    assert_int_equal(5, out_len);
    assert_memory_equal("Hello", out, 5);
    free(out);
}

static void test_decode_wrong_prefix(void **state)
{
    (void)state;
    unsigned char *out = NULL;
    size_t out_len = 0;
    assert_int_equal(-1, vault_response_decode("hmac:v1:SGVsbG8=",
                                                &out, &out_len));
}

static void test_decode_missing_prefix(void **state)
{
    (void)state;
    unsigned char *out = NULL;
    size_t out_len = 0;
    assert_int_equal(-1, vault_response_decode("SGVsbG8=", &out, &out_len));
}

static void test_decode_null(void **state)
{
    (void)state;
    unsigned char *out = NULL;
    size_t out_len = 0;
    assert_int_equal(-1, vault_response_decode(NULL, &out, &out_len));
}

static void test_decode_binary_payload(void **state)
{
    (void)state;
    /* Known base64 of 3 bytes: 0xDE 0xAD 0xBE */
    unsigned char *out = NULL;
    size_t out_len = 0;
    assert_int_equal(0, vault_response_decode("vault:v1:3q2+",
                                               &out, &out_len));
    assert_int_equal(3, out_len);
    assert_int_equal(0xde, out[0]);
    assert_int_equal(0xad, out[1]);
    assert_int_equal(0xbe, out[2]);
    free(out);
}

/* ── vault_hash_alg_name ─────────────────────────────────────────────── */

static void test_hash_alg_sha256(void **state)
{
    (void)state;
    assert_string_equal("sha2-256", vault_hash_alg_name(NID_sha256));
}

static void test_hash_alg_sha384(void **state)
{
    (void)state;
    assert_string_equal("sha2-384", vault_hash_alg_name(NID_sha384));
}

static void test_hash_alg_sha512(void **state)
{
    (void)state;
    assert_string_equal("sha2-512", vault_hash_alg_name(NID_sha512));
}

static void test_hash_alg_sha1(void **state)
{
    (void)state;
    assert_string_equal("sha1", vault_hash_alg_name(NID_sha1));
}

static void test_hash_alg_sha3_256(void **state)
{
    (void)state;
    assert_string_equal("sha3-256", vault_hash_alg_name(NID_sha3_256));
}

static void test_hash_alg_unknown(void **state)
{
    (void)state;
    assert_null(vault_hash_alg_name(NID_md5));
}

/* ── vault_key_type_name ─────────────────────────────────────────────── */

static void test_key_type_rsa_2048(void **state)
{
    (void)state;
    assert_string_equal("rsa-2048",
        vault_key_type_name(EVP_PKEY_RSA, 2048, 0));
}

static void test_key_type_rsa_3072(void **state)
{
    (void)state;
    assert_string_equal("rsa-3072",
        vault_key_type_name(EVP_PKEY_RSA, 3072, 0));
}

static void test_key_type_rsa_4096(void **state)
{
    (void)state;
    assert_string_equal("rsa-4096",
        vault_key_type_name(EVP_PKEY_RSA, 4096, 0));
}

static void test_key_type_rsa_unsupported_size(void **state)
{
    (void)state;
    assert_null(vault_key_type_name(EVP_PKEY_RSA, 1024, 0));
}

static void test_key_type_ec_p256(void **state)
{
    (void)state;
    assert_string_equal("ecdsa-p256",
        vault_key_type_name(EVP_PKEY_EC, 0, NID_X9_62_prime256v1));
}

static void test_key_type_ec_p384(void **state)
{
    (void)state;
    assert_string_equal("ecdsa-p384",
        vault_key_type_name(EVP_PKEY_EC, 0, NID_secp384r1));
}

static void test_key_type_ec_p521(void **state)
{
    (void)state;
    assert_string_equal("ecdsa-p521",
        vault_key_type_name(EVP_PKEY_EC, 0, NID_secp521r1));
}

static void test_key_type_ed25519(void **state)
{
    (void)state;
    assert_string_equal("ed25519",
        vault_key_type_name(EVP_PKEY_ED25519, 0, 0));
}

static void test_key_type_unknown(void **state)
{
    (void)state;
    assert_null(vault_key_type_name(EVP_PKEY_DH, 0, 0));
}

/* ── vault_response_encode ───────────────────────────────────────────── */

static void test_response_encode_hello(void **state)
{
    (void)state;
    const unsigned char in[] = "Hello";
    char *enc = vault_response_encode(in, 5);
    assert_non_null(enc);
    assert_string_equal(enc, "vault:v1:SGVsbG8=");
    free(enc);
}

static void test_response_encode_decode_roundtrip(void **state)
{
    (void)state;
    const unsigned char orig[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };
    char *encoded = vault_response_encode(orig, sizeof(orig));
    assert_non_null(encoded);

    /* Must have the vault:v1: prefix. */
    assert_true(strncmp(encoded, "vault:v1:", 9) == 0);

    unsigned char *decoded = NULL;
    size_t decoded_len = 0;
    assert_int_equal(0, vault_response_decode(encoded, &decoded, &decoded_len));
    assert_int_equal(sizeof(orig), decoded_len);
    assert_memory_equal(orig, decoded, sizeof(orig));

    free(encoded);
    free(decoded);
}

/* ── vault_base64_decode ─────────────────────────────────────────────── */

static void test_base64_decode_hello(void **state)
{
    (void)state;
    unsigned char *out = NULL;
    size_t out_len = 0;
    assert_int_equal(0, vault_base64_decode("SGVsbG8=", &out, &out_len));
    assert_int_equal(5, out_len);
    assert_memory_equal("Hello", out, 5);
    free(out);
}

static void test_base64_decode_binary(void **state)
{
    (void)state;
    /* 0xDE 0xAD 0xBE = "3q2+" in base64 */
    unsigned char *out = NULL;
    size_t out_len = 0;
    assert_int_equal(0, vault_base64_decode("3q2+", &out, &out_len));
    assert_int_equal(3, out_len);
    assert_int_equal(0xde, out[0]);
    assert_int_equal(0xad, out[1]);
    assert_int_equal(0xbe, out[2]);
    free(out);
}

static void test_base64_decode_encode_roundtrip(void **state)
{
    (void)state;
    const unsigned char orig[8] = {0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xc0, 0xde};
    char *b64 = vault_request_encode(orig, sizeof(orig));
    assert_non_null(b64);

    unsigned char *decoded = NULL;
    size_t decoded_len = 0;
    assert_int_equal(0, vault_base64_decode(b64, &decoded, &decoded_len));
    assert_int_equal(sizeof(orig), decoded_len);
    assert_memory_equal(orig, decoded, sizeof(orig));

    free(b64);
    free(decoded);
}

static void test_base64_decode_null(void **state)
{
    (void)state;
    unsigned char *out = NULL;
    size_t out_len = 0;
    assert_int_equal(-1, vault_base64_decode(NULL, &out, &out_len));
}

/* ── OOM tests ───────────────────────────────────────────────────────── */
/*
 * libcrypto is a shared library, so its internal BIO allocations are NOT
 * intercepted by --wrap,malloc.  The first wrapped malloc in each function
 * below is the one that copies the result out of the BIO into a heap buffer.
 */

static void test_oom_request_encode(void **state)
{
    (void)state;
    const unsigned char in[] = "Hello";

    wrap_malloc_fail_after(0);   /* malloc(bm->length+1) in vault_request_encode */
    char *enc = vault_request_encode(in, 5);
    assert_null(enc);
}

static void test_oom_response_decode(void **state)
{
    (void)state;
    unsigned char *out = NULL;
    size_t out_len = 0;

    wrap_malloc_fail_after(0);   /* malloc(max_out) in vault_response_decode */
    int rc = vault_response_decode("vault:v1:SGVsbG8=", &out, &out_len);
    assert_int_equal(-1, rc);
    assert_null(out);
}

static void test_oom_base64_decode(void **state)
{
    (void)state;
    unsigned char *out = NULL;
    size_t out_len = 0;

    wrap_malloc_fail_after(0);   /* malloc(max_out) in vault_base64_decode */
    int rc = vault_base64_decode("SGVsbG8=", &out, &out_len);
    assert_int_equal(-1, rc);
    assert_null(out);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_encode_hello),
        cmocka_unit_test(test_encode_roundtrip),
        cmocka_unit_test(test_encode_null_data),

        cmocka_unit_test(test_decode_hello),
        cmocka_unit_test(test_decode_wrong_prefix),
        cmocka_unit_test(test_decode_missing_prefix),
        cmocka_unit_test(test_decode_null),
        cmocka_unit_test(test_decode_binary_payload),

        cmocka_unit_test(test_hash_alg_sha256),
        cmocka_unit_test(test_hash_alg_sha384),
        cmocka_unit_test(test_hash_alg_sha512),
        cmocka_unit_test(test_hash_alg_sha1),
        cmocka_unit_test(test_hash_alg_sha3_256),
        cmocka_unit_test(test_hash_alg_unknown),

        cmocka_unit_test(test_key_type_rsa_2048),
        cmocka_unit_test(test_key_type_rsa_3072),
        cmocka_unit_test(test_key_type_rsa_4096),
        cmocka_unit_test(test_key_type_rsa_unsupported_size),
        cmocka_unit_test(test_key_type_ec_p256),
        cmocka_unit_test(test_key_type_ec_p384),
        cmocka_unit_test(test_key_type_ec_p521),
        cmocka_unit_test(test_key_type_ed25519),
        cmocka_unit_test(test_key_type_unknown),

        cmocka_unit_test(test_response_encode_hello),
        cmocka_unit_test(test_response_encode_decode_roundtrip),

        cmocka_unit_test(test_base64_decode_hello),
        cmocka_unit_test(test_base64_decode_binary),
        cmocka_unit_test(test_base64_decode_encode_roundtrip),
        cmocka_unit_test(test_base64_decode_null),

        cmocka_unit_test(test_oom_request_encode),
        cmocka_unit_test(test_oom_response_decode),
        cmocka_unit_test(test_oom_base64_decode),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
