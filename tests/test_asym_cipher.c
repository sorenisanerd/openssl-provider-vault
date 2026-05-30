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

/*
 * Unit tests for asym_cipher.c — RSA-OAEP encrypt/decrypt via Vault.
 *
 * Uses mock_vault_client.c and wrap_malloc.c; no network required.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include "vault_keyref.h"
#include "asym_cipher.h"
#include "provider.h"
#include "wrap_malloc.h"

/* ── fixtures ─────────────────────────────────────────────────────────── */

static vault_provctx_t g_provctx;

static vault_keyref_t g_key = {
    .key_name    = "my-rsa-key",
    .key_version = 1,
    .key_type    = "rsa-2048",
    .pubkey_der  = NULL,
    .pubkey_der_len = 0,
};

/* ── helpers ──────────────────────────────────────────────────────────── */

static void *make_ctx(void)
{
    return vault_asym_cipher_newctx(&g_provctx, NULL);
}

/* ── tests ────────────────────────────────────────────────────────────── */

static void test_asym_encrypt_basic(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);

    assert_int_equal(1, vault_asym_cipher_encrypt_init(ctx, &g_key, NULL));

    static const unsigned char plaintext[] = "hello";
    static const unsigned char fake_ct[]   = "vault:v1:AAAA";

    expect_string(vault_asym_encrypt, key_name, "my-rsa-key");
    expect_value(vault_asym_encrypt, key_version, 1);
    expect_value(vault_asym_encrypt, plaintext_len, sizeof(plaintext));
    will_return(vault_asym_encrypt, fake_ct);
    will_return(vault_asym_encrypt, sizeof(fake_ct));
    will_return(vault_asym_encrypt, 0);

    unsigned char out[256];
    size_t outlen = 0;
    assert_int_equal(1, vault_asym_cipher_encrypt(ctx, out, &outlen,
                                                   sizeof(out),
                                                   plaintext, sizeof(plaintext)));
    assert_int_equal(sizeof(fake_ct), outlen);
    assert_memory_equal(fake_ct, out, outlen);

    vault_asym_cipher_freectx(ctx);
}

static void test_asym_decrypt_basic(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);

    assert_int_equal(1, vault_asym_cipher_decrypt_init(ctx, &g_key, NULL));

    static const unsigned char ciphertext[] = "vault:v1:AAAA";
    static const unsigned char fake_pt[]    = "hello";

    expect_string(vault_asym_decrypt, key_name, "my-rsa-key");
    expect_value(vault_asym_decrypt, key_version, 1);
    expect_value(vault_asym_decrypt, ciphertext_len, sizeof(ciphertext));
    will_return(vault_asym_decrypt, fake_pt);
    will_return(vault_asym_decrypt, sizeof(fake_pt));
    will_return(vault_asym_decrypt, 0);

    unsigned char out[256];
    size_t outlen = 0;
    assert_int_equal(1, vault_asym_cipher_decrypt(ctx, out, &outlen,
                                                   sizeof(out),
                                                   ciphertext, sizeof(ciphertext)));
    assert_int_equal(sizeof(fake_pt), outlen);
    assert_memory_equal(fake_pt, out, outlen);

    vault_asym_cipher_freectx(ctx);
}

static void test_asym_encrypt_size_query(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_asym_cipher_encrypt_init(ctx, &g_key, NULL));

    size_t outlen = 0;
    /* out == NULL → size query, no vault call */
    assert_int_equal(1, vault_asym_cipher_encrypt(ctx, NULL, &outlen, 0,
                                                   (unsigned char *)"x", 1));
    assert_true(outlen > 0);
    vault_asym_cipher_freectx(ctx);
}

static void test_asym_decrypt_size_query(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_asym_cipher_decrypt_init(ctx, &g_key, NULL));

    size_t outlen = 0;
    assert_int_equal(1, vault_asym_cipher_decrypt(ctx, NULL, &outlen, 0,
                                                   (unsigned char *)"x", 1));
    assert_true(outlen > 0);
    vault_asym_cipher_freectx(ctx);
}

static void test_asym_encrypt_vault_error(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_asym_cipher_encrypt_init(ctx, &g_key, NULL));

    static const unsigned char plaintext[] = "data";
    expect_string(vault_asym_encrypt, key_name, "my-rsa-key");
    expect_value(vault_asym_encrypt, key_version, 1);
    expect_value(vault_asym_encrypt, plaintext_len, sizeof(plaintext));
    will_return(vault_asym_encrypt, NULL);
    will_return(vault_asym_encrypt, (size_t)0);
    will_return(vault_asym_encrypt, -1);  /* vault returns error */

    unsigned char out[256];
    size_t outlen = 0;
    assert_int_equal(0, vault_asym_cipher_encrypt(ctx, out, &outlen,
                                                   sizeof(out),
                                                   plaintext, sizeof(plaintext)));
    vault_asym_cipher_freectx(ctx);
}

static void test_asym_decrypt_vault_error(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_asym_cipher_decrypt_init(ctx, &g_key, NULL));

    static const unsigned char ct[] = "vault:v1:AAAA";
    expect_string(vault_asym_decrypt, key_name, "my-rsa-key");
    expect_value(vault_asym_decrypt, key_version, 1);
    expect_value(vault_asym_decrypt, ciphertext_len, sizeof(ct));
    will_return(vault_asym_decrypt, NULL);
    will_return(vault_asym_decrypt, (size_t)0);
    will_return(vault_asym_decrypt, -1);

    unsigned char out[256];
    size_t outlen = 0;
    assert_int_equal(0, vault_asym_cipher_decrypt(ctx, out, &outlen,
                                                   sizeof(out),
                                                   ct, sizeof(ct)));
    vault_asym_cipher_freectx(ctx);
}

static void test_asym_encrypt_oom_newctx(void **state)
{
    (void)state;
    wrap_malloc_fail_after(0);
    void *ctx = vault_asym_cipher_newctx(&g_provctx, NULL);
    wrap_malloc_fail_after(-1);
    assert_null(ctx);
}

static void test_asym_dupctx_basic(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_asym_cipher_encrypt_init(ctx, &g_key, NULL));

    void *dup = vault_asym_cipher_dupctx(ctx);
    assert_non_null(dup);

    vault_asym_cipher_freectx(ctx);
    vault_asym_cipher_freectx(dup);
}

static void test_asym_encrypt_oom_dupctx(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);

    wrap_malloc_fail_after(0);
    void *dup = vault_asym_cipher_dupctx(ctx);
    wrap_malloc_fail_after(-1);
    assert_null(dup);

    vault_asym_cipher_freectx(ctx);
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_asym_encrypt_basic),
        cmocka_unit_test(test_asym_decrypt_basic),
        cmocka_unit_test(test_asym_encrypt_size_query),
        cmocka_unit_test(test_asym_decrypt_size_query),
        cmocka_unit_test(test_asym_encrypt_vault_error),
        cmocka_unit_test(test_asym_decrypt_vault_error),
        cmocka_unit_test(test_asym_encrypt_oom_newctx),
        cmocka_unit_test(test_asym_dupctx_basic),
        cmocka_unit_test(test_asym_encrypt_oom_dupctx),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
