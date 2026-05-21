/*
 * Integration tests for vault_client.c.
 *
 * If VAULT_ADDR and VAULT_TOKEN are already set the tests use that server.
 * Otherwise, if the vault(1) binary is found on PATH, a local dev server is
 * started automatically on 127.0.0.1:18200 and torn down when the suite
 * finishes.  If neither condition is met the suite is skipped (exit 77).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <curl/curl.h>

#include "vault_client.h"
#include "vault_format.h"
#include "wrap_malloc.h"

/* ── managed Vault dev-server ────────────────────────────────────────── */

static pid_t g_vault_pid = -1;

static void stop_managed_vault(void)
{
    if (g_vault_pid > 0) {
        kill(g_vault_pid, SIGTERM);
        waitpid(g_vault_pid, NULL, 0);
        g_vault_pid = -1;
    }
}

/*
 * Start "vault server -dev" on 127.0.0.1:18200, wait up to ~5 s for it to
 * become ready, then enable the transit secrets engine.
 * Returns 0 on success, -1 if the server could not be started.
 */
static int start_managed_vault(void)
{
    g_vault_pid = fork();
    if (g_vault_pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("vault", "vault", "server",
               "-dev",
               "-dev-root-token-id=root",
               "-dev-listen-address=127.0.0.1:18200",
               (char *)NULL);
        _exit(1);
    }
    if (g_vault_pid < 0) return -1;

    setenv("VAULT_ADDR",  "http://127.0.0.1:18200", 1);
    setenv("VAULT_TOKEN", "root", 1);

    /* Poll until vault reports unsealed (exit 0) or we time out (~5 s). */
    for (int i = 0; i < 20; i++) {
        usleep(250000);
        if (system("vault status >/dev/null 2>&1") == 0)
            goto ready;
    }
    stop_managed_vault();
    return -1;

ready:;
    int r = system("vault secrets enable transit >/dev/null 2>&1"); (void)r;
    return 0;
}

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

/* ── OOM tests (no Vault server required) ────────────────────────────── */

static void test_oom_ctx_new(void **state)
{
    (void)state;
    wrap_malloc_fail_after(0);   /* calloc for vault_ctx_t */
    vault_ctx_t *ctx = vault_ctx_new("http://vault:8200", "tok", NULL);
    assert_null(ctx);
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(void)
{
    /* OOM tests run unconditionally — no live Vault needed. */
    const struct CMUnitTest oom_tests[] = {
        cmocka_unit_test(test_oom_ctx_new),
    };
    int oom_result = cmocka_run_group_tests_name("vault_client oom",
                                                  oom_tests, NULL, NULL);

    int managed = 0;

    if (!vault_addr() || !vault_token()) {
        /* No external Vault configured — try to start one ourselves. */
        if (system("vault version >/dev/null 2>&1") != 0)
            return oom_result ? oom_result : 77;
        if (start_managed_vault() != 0)
            return oom_result ? oom_result : 77;
        managed = 1;
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
    int result = cmocka_run_group_tests_name("vault_client integration",
                                             tests,
                                             suite_setup, suite_teardown);

    if (managed)
        stop_managed_vault();

    return oom_result || result;
}
