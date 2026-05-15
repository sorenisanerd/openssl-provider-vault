/*
 * Integration tests for vault_client.c.
 *
 * These tests require a running Vault dev server.  Set the environment:
 *
 *   VAULT_ADDR=http://127.0.0.1:8200
 *   VAULT_TOKEN=root
 *
 * Quick start:
 *   vault server -dev -dev-root-token-id=root &
 *   vault secrets enable transit
 *
 * If the variables are absent the whole suite is skipped (exit 77).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "vault_client.h"
#include "vault_format.h"

/* ── test fixture ────────────────────────────────────────────────────── */

static vault_ctx_t *g_ctx = NULL;

static const char *vault_addr(void)  { return getenv("VAULT_ADDR");  }
static const char *vault_token(void) { return getenv("VAULT_TOKEN"); }

static int suite_setup(void **state)
{
    (void)state;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    g_ctx = vault_ctx_new(vault_addr(), vault_token(), NULL);
    return g_ctx ? 0 : -1;
}

static int suite_teardown(void **state)
{
    (void)state;
    vault_ctx_free(g_ctx);
    curl_global_cleanup();
    return 0;
}

/* ── helpers ─────────────────────────────────────────────────────────── */

static void run_cmd(const char *fmt, ...)
{
    char cmd[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    int r = system(cmd); (void)r;
}

/* Delete a key so tests start from a clean state. */
static void delete_key(const char *name)
{
    run_cmd("VAULT_ADDR=%s VAULT_TOKEN=%s "
            "vault write -f transit/keys/%s/config deletion_allowed=true "
            ">/dev/null 2>&1",
            vault_addr(), vault_token(), name);
    run_cmd("VAULT_ADDR=%s VAULT_TOKEN=%s "
            "vault delete transit/keys/%s >/dev/null 2>&1",
            vault_addr(), vault_token(), name);
}

/* ── vault_create_key / vault_get_key ────────────────────────────────── */

static void test_create_and_get_rsa_key(void **state)
{
    (void)state;
    const char *name = "test-int-rsa-2048";
    delete_key(name);

    assert_int_equal(0, vault_create_key(g_ctx, name, "rsa-2048", 0));

    vault_key_info_t info = {0};
    assert_int_equal(0, vault_get_key(g_ctx, name, &info));
    assert_string_equal("rsa-2048", info.key_type);
    assert_int_equal(1, info.latest_version);
    assert_non_null(info.pubkey_der);
    assert_true(info.pubkey_der_len > 0);

    vault_key_info_free(&info);
    delete_key(name);
}

static void test_create_and_get_ec_key(void **state)
{
    (void)state;
    const char *name = "test-int-ecdsa-p256";
    delete_key(name);

    assert_int_equal(0, vault_create_key(g_ctx, name, "ecdsa-p256", 0));

    vault_key_info_t info = {0};
    assert_int_equal(0, vault_get_key(g_ctx, name, &info));
    assert_string_equal("ecdsa-p256", info.key_type);
    assert_non_null(info.pubkey_der);

    vault_key_info_free(&info);
    delete_key(name);
}

static void test_get_nonexistent_key_fails(void **state)
{
    (void)state;
    vault_key_info_t info = {0};
    assert_int_not_equal(0, vault_get_key(g_ctx, "nonexistent-key-xyz", &info));
}

/* ── sign / verify roundtrip ─────────────────────────────────────────── */

static void test_sign_verify_rsa_pss(void **state)
{
    (void)state;
    const char *name = "test-int-sign-rsa";
    delete_key(name);
    assert_int_equal(0, vault_create_key(g_ctx, name, "rsa-2048", 0));

    /* Fake SHA-256 digest. */
    unsigned char digest[32];
    memset(digest, 0x42, sizeof(digest));

    unsigned char *sig     = NULL;
    size_t         sig_len = 0;
    assert_int_equal(0,
        vault_sign(g_ctx, name, 0, "sha2-256", "pss",
                   digest, sizeof(digest), &sig, &sig_len));
    assert_non_null(sig);
    assert_true(sig_len > 0);

    int valid = 0;
    assert_int_equal(0,
        vault_verify(g_ctx, name, 0, "sha2-256", "pss",
                     digest, sizeof(digest), sig, sig_len, &valid));
    assert_int_equal(1, valid);

    free(sig);
    delete_key(name);
}

static void test_sign_verify_ecdsa(void **state)
{
    (void)state;
    const char *name = "test-int-sign-ec";
    delete_key(name);
    assert_int_equal(0, vault_create_key(g_ctx, name, "ecdsa-p256", 0));

    unsigned char digest[32];
    memset(digest, 0x77, sizeof(digest));

    unsigned char *sig     = NULL;
    size_t         sig_len = 0;
    assert_int_equal(0,
        vault_sign(g_ctx, name, 0, "sha2-256", "pss",
                   digest, sizeof(digest), &sig, &sig_len));
    assert_non_null(sig);

    int valid = 0;
    assert_int_equal(0,
        vault_verify(g_ctx, name, 0, "sha2-256", "pss",
                     digest, sizeof(digest), sig, sig_len, &valid));
    assert_int_equal(1, valid);

    free(sig);
    delete_key(name);
}

static void test_verify_wrong_digest_fails(void **state)
{
    (void)state;
    const char *name = "test-int-verify-bad";
    delete_key(name);
    assert_int_equal(0, vault_create_key(g_ctx, name, "rsa-2048", 0));

    unsigned char digest[32];
    memset(digest, 0x11, sizeof(digest));

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    vault_sign(g_ctx, name, 0, "sha2-256", "pss",
               digest, sizeof(digest), &sig, &sig_len);

    /* Verify against a different digest — should report invalid. */
    unsigned char other[32];
    memset(other, 0x22, sizeof(other));
    int valid = 1;
    assert_int_equal(0,
        vault_verify(g_ctx, name, 0, "sha2-256", "pss",
                     other, sizeof(other), sig, sig_len, &valid));
    assert_int_equal(0, valid);

    free(sig);
    delete_key(name);
}

/* ── symmetric encrypt / decrypt ─────────────────────────────────────── */

static void test_sym_encrypt_decrypt(void **state)
{
    (void)state;
    const char *name = "test-int-sym-aes";
    delete_key(name);
    assert_int_equal(0, vault_create_key(g_ctx, name, "aes256-gcm96", 0));

    const unsigned char plaintext[] = "Hello, Vault transit!";
    size_t plaintext_len = sizeof(plaintext) - 1;

    unsigned char *ciphertext = NULL;
    size_t ct_len = 0;
    assert_int_equal(0,
        vault_sym_encrypt(g_ctx, name, 0,
                          plaintext, plaintext_len,
                          &ciphertext, &ct_len));
    assert_non_null(ciphertext);
    assert_true(ct_len > 0);

    unsigned char *recovered = NULL;
    size_t rec_len = 0;
    assert_int_equal(0,
        vault_sym_decrypt(g_ctx, name, 0,
                          ciphertext, ct_len,
                          &recovered, &rec_len));
    assert_non_null(recovered);
    assert_int_equal(plaintext_len, rec_len);
    assert_memory_equal(plaintext, recovered, plaintext_len);

    free(ciphertext);
    free(recovered);
    delete_key(name);
}

/* ── HMAC ─────────────────────────────────────────────────────────────── */

static void test_hmac_stable(void **state)
{
    (void)state;
    const char *name = "test-int-hmac";
    delete_key(name);
    assert_int_equal(0, vault_create_key(g_ctx, name, "hmac", 0));

    const unsigned char msg[] = "test message";
    unsigned char *mac1 = NULL, *mac2 = NULL;
    size_t mac1_len = 0, mac2_len = 0;

    assert_int_equal(0,
        vault_hmac(g_ctx, name, 0, "sha2-256",
                   msg, sizeof(msg) - 1, &mac1, &mac1_len));
    assert_int_equal(0,
        vault_hmac(g_ctx, name, 0, "sha2-256",
                   msg, sizeof(msg) - 1, &mac2, &mac2_len));

    /* HMAC of the same input with the same key must be stable. */
    assert_int_equal(mac1_len, mac2_len);
    assert_memory_equal(mac1, mac2, mac1_len);

    free(mac1);
    free(mac2);
    delete_key(name);
}

/* ── vault_random ─────────────────────────────────────────────────────── */

static void test_random_correct_length(void **state)
{
    (void)state;
    unsigned char *rand_bytes = NULL;
    assert_int_equal(0, vault_random(g_ctx, 32, &rand_bytes));
    assert_non_null(rand_bytes);
    /* We can't assert the value, but we can check it doesn't crash. */
    free(rand_bytes);
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(void)
{
    if (!vault_addr() || !vault_token()) {
        /* Exit 77 = autotest SKIP — no Vault dev server configured. */
        return 77;
    }

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_and_get_rsa_key),
        cmocka_unit_test(test_create_and_get_ec_key),
        cmocka_unit_test(test_get_nonexistent_key_fails),

        cmocka_unit_test(test_sign_verify_rsa_pss),
        cmocka_unit_test(test_sign_verify_ecdsa),
        cmocka_unit_test(test_verify_wrong_digest_fails),

        cmocka_unit_test(test_sym_encrypt_decrypt),

        cmocka_unit_test(test_hmac_stable),

        cmocka_unit_test(test_random_correct_length),
    };
    return cmocka_run_group_tests_name("vault_client integration",
                                       tests,
                                       suite_setup, suite_teardown);
}
