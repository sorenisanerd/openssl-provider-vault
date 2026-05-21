/*
 * Unit tests for mac.c — HMAC via Vault.
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
#include "mac.h"
#include "provider.h"
#include "wrap_malloc.h"

#include <openssl/core_names.h>
#include <openssl/params.h>

/* ── fixtures ─────────────────────────────────────────────────────────── */

static vault_provctx_t g_provctx;

static vault_keyref_t g_key = {
    .key_name    = "my-hmac-key",
    .key_version = 1,
    .key_type    = "hmac",
    .pubkey_der  = NULL,
    .pubkey_der_len = 0,
};

/* ── helpers ──────────────────────────────────────────────────────────── */

static void *make_ctx(void)
{
    return vault_mac_newctx(&g_provctx);
}

/* ── tests ────────────────────────────────────────────────────────────── */

static void test_mac_hmac_basic(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);

    assert_int_equal(1, vault_mac_init_skey(ctx, &g_key, NULL));

    static const unsigned char data[] = "hello world";
    assert_int_equal(1, vault_mac_update(ctx, data, sizeof(data)));

    static const unsigned char fake_hmac[32] = { 0xde, 0xad, [31] = 0xbe };

    expect_string(vault_hmac, key_name, "my-hmac-key");
    expect_value(vault_hmac, key_version, 1);
    expect_string(vault_hmac, algorithm, "sha2-256");
    expect_value(vault_hmac, input_len, sizeof(data));
    will_return(vault_hmac, fake_hmac);
    will_return(vault_hmac, (size_t)32);
    will_return(vault_hmac, 0);

    unsigned char out[64];
    size_t outlen = 0;
    assert_int_equal(1, vault_mac_final(ctx, out, &outlen, sizeof(out)));
    assert_int_equal(32, outlen);
    assert_memory_equal(fake_hmac, out, 32);

    vault_mac_freectx(ctx);
}

static void test_mac_final_size_query(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_mac_init_skey(ctx, &g_key, NULL));

    size_t outlen = 0;
    /* out==NULL → size query, no vault call */
    assert_int_equal(1, vault_mac_final(ctx, NULL, &outlen, 0));
    assert_true(outlen > 0);

    vault_mac_freectx(ctx);
}

static void test_mac_vault_error(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_mac_init_skey(ctx, &g_key, NULL));

    static const unsigned char data[] = "msg";
    assert_int_equal(1, vault_mac_update(ctx, data, sizeof(data)));

    expect_string(vault_hmac, key_name, "my-hmac-key");
    expect_value(vault_hmac, key_version, 1);
    expect_string(vault_hmac, algorithm, "sha2-256");
    expect_value(vault_hmac, input_len, sizeof(data));
    will_return(vault_hmac, NULL);
    will_return(vault_hmac, (size_t)0);
    will_return(vault_hmac, -1);

    unsigned char out[64];
    size_t outlen = 0;
    assert_int_equal(0, vault_mac_final(ctx, out, &outlen, sizeof(out)));

    vault_mac_freectx(ctx);
}

static void test_mac_multi_update(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_mac_init_skey(ctx, &g_key, NULL));

    static const unsigned char part1[] = "hello";
    static const unsigned char part2[] = " world";
    assert_int_equal(1, vault_mac_update(ctx, part1, sizeof(part1)));
    assert_int_equal(1, vault_mac_update(ctx, part2, sizeof(part2)));

    static const unsigned char fake_hmac[32] = { 0xab };
    /* Vault should receive the concatenated length */
    expect_string(vault_hmac, key_name, "my-hmac-key");
    expect_value(vault_hmac, key_version, 1);
    expect_string(vault_hmac, algorithm, "sha2-256");
    expect_value(vault_hmac, input_len, sizeof(part1) + sizeof(part2));
    will_return(vault_hmac, fake_hmac);
    will_return(vault_hmac, (size_t)32);
    will_return(vault_hmac, 0);

    unsigned char out[64];
    size_t outlen = 0;
    assert_int_equal(1, vault_mac_final(ctx, out, &outlen, sizeof(out)));
    assert_int_equal(32, outlen);

    vault_mac_freectx(ctx);
}

static void test_mac_set_digest_param(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_mac_init_skey(ctx, &g_key, NULL));

    /* Override digest to SHA-512 */
    const char *digest_name = "SHA512";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                         (char *)digest_name, 0),
        OSSL_PARAM_construct_end(),
    };
    assert_int_equal(1, vault_mac_set_ctx_params(ctx, params));

    static const unsigned char data[] = "data";
    assert_int_equal(1, vault_mac_update(ctx, data, sizeof(data)));

    static const unsigned char fake_hmac[64] = { 0x01 };
    expect_string(vault_hmac, key_name, "my-hmac-key");
    expect_value(vault_hmac, key_version, 1);
    expect_string(vault_hmac, algorithm, "sha2-512");
    expect_value(vault_hmac, input_len, sizeof(data));
    will_return(vault_hmac, fake_hmac);
    will_return(vault_hmac, (size_t)64);
    will_return(vault_hmac, 0);

    unsigned char out[128];
    size_t outlen = 0;
    assert_int_equal(1, vault_mac_final(ctx, out, &outlen, sizeof(out)));
    assert_int_equal(64, outlen);

    vault_mac_freectx(ctx);
}

static void test_mac_oom_newctx(void **state)
{
    (void)state;
    wrap_malloc_fail_after(0);
    void *ctx = vault_mac_newctx(&g_provctx);
    wrap_malloc_fail_after(-1);
    assert_null(ctx);
}

static void test_mac_oom_update(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_mac_init_skey(ctx, &g_key, NULL));

    static const unsigned char data[] = "hello";
    wrap_malloc_fail_after(0);
    int rc = vault_mac_update(ctx, data, sizeof(data));
    wrap_malloc_fail_after(-1);
    assert_int_equal(0, rc);

    vault_mac_freectx(ctx);
}

static void test_mac_dupctx_basic(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_mac_init_skey(ctx, &g_key, NULL));

    static const unsigned char data[] = "partial";
    assert_int_equal(1, vault_mac_update(ctx, data, sizeof(data)));

    void *dup = vault_mac_dupctx(ctx);
    assert_non_null(dup);

    vault_mac_freectx(ctx);
    vault_mac_freectx(dup);
}

static void test_mac_oom_dupctx(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_mac_init_skey(ctx, &g_key, NULL));

    static const unsigned char data[] = "data";
    assert_int_equal(1, vault_mac_update(ctx, data, sizeof(data)));

    /* First malloc is for the dst struct, second would be for data_buf copy */
    wrap_malloc_fail_after(0);
    void *dup = vault_mac_dupctx(ctx);
    wrap_malloc_fail_after(-1);
    assert_null(dup);

    vault_mac_freectx(ctx);
}

static void test_mac_oom_dupctx_databuf(void **state)
{
    (void)state;
    void *ctx = make_ctx();
    assert_non_null(ctx);
    assert_int_equal(1, vault_mac_init_skey(ctx, &g_key, NULL));

    static const unsigned char data[] = "data";
    assert_int_equal(1, vault_mac_update(ctx, data, sizeof(data)));

    /* Let the struct malloc succeed, fail the data_buf malloc */
    wrap_malloc_fail_after(1);
    void *dup = vault_mac_dupctx(ctx);
    wrap_malloc_fail_after(-1);
    assert_null(dup);

    vault_mac_freectx(ctx);
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_mac_hmac_basic),
        cmocka_unit_test(test_mac_final_size_query),
        cmocka_unit_test(test_mac_vault_error),
        cmocka_unit_test(test_mac_multi_update),
        cmocka_unit_test(test_mac_set_digest_param),
        cmocka_unit_test(test_mac_oom_newctx),
        cmocka_unit_test(test_mac_oom_update),
        cmocka_unit_test(test_mac_dupctx_basic),
        cmocka_unit_test(test_mac_oom_dupctx),
        cmocka_unit_test(test_mac_oom_dupctx_databuf),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
