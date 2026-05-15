/*
 * cmocka-based mock for vault_client.h.
 *
 * Each function uses check_expected() to assert that the caller passed the
 * right arguments, then will_return() to control its return values.
 *
 * Tests set expectations with expect_*() and will_return() before exercising
 * the code under test.  Output parameters (sig_out, plaintext_out, etc.) are
 * set by having the test place a pointer+length in the will_return queue;
 * the mock malloc-copies the bytes so the caller can free() them normally.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include "vault_client.h"

/* vault_ctx_t is opaque; tests pass NULL and mocks ignore it. */
struct vault_ctx { int unused; };

vault_ctx_t *vault_ctx_new(const char *addr, const char *token, const char *ns)
{
    (void)addr; (void)token; (void)ns;
    static vault_ctx_t dummy;
    return &dummy;
}

void vault_ctx_free(vault_ctx_t *ctx) { (void)ctx; }

/* ── vault_get_key ───────────────────────────────────────────────────── */

int vault_get_key(vault_ctx_t *ctx, const char *key_name,
                  vault_key_info_t *info_out)
{
    (void)ctx;
    check_expected(key_name);

    /* The test queues: key_type string, pubkey_der pointer, der_len,
     * latest_version, return code — in that order. */
    const char *key_type    = mock_ptr_type(const char *);
    const unsigned char *der = mock_ptr_type(const unsigned char *);
    size_t der_len           = mock_type(size_t);
    int    latest            = mock_type(int);
    int    ret               = mock_type(int);

    if (ret == 0) {
        info_out->key_type       = strdup(key_type);
        info_out->latest_version = latest;
        if (der && der_len) {
            info_out->pubkey_der = malloc(der_len);
            memcpy(info_out->pubkey_der, der, der_len);
            info_out->pubkey_der_len = der_len;
        }
    }
    return ret;
}

void vault_key_info_free(vault_key_info_t *info)
{
    if (!info) return;
    free(info->key_type);
    free(info->pubkey_der);
}

/* ── vault_create_key ────────────────────────────────────────────────── */

int vault_create_key(vault_ctx_t *ctx, const char *key_name,
                     const char *key_type, int exportable)
{
    (void)ctx;
    check_expected(key_name);
    check_expected(key_type);
    check_expected(exportable);
    return mock_type(int);
}

/* ── vault_sign ──────────────────────────────────────────────────────── */

int vault_sign(vault_ctx_t *ctx,
               const char *key_name, int key_version,
               const char *hash_alg, const char *sig_alg,
               const unsigned char *input, size_t input_len,
               unsigned char **sig_out, size_t *sig_out_len)
{
    (void)ctx;
    check_expected(key_name);
    check_expected(key_version);
    check_expected(hash_alg);
    check_expected(sig_alg);
    check_expected(input_len);

    const unsigned char *sig_data = mock_ptr_type(const unsigned char *);
    size_t               sig_len  = mock_type(size_t);
    int                  ret      = mock_type(int);

    if (ret == 0 && sig_data) {
        *sig_out     = malloc(sig_len);
        memcpy(*sig_out, sig_data, sig_len);
        *sig_out_len = sig_len;
    }
    return ret;
}

/* ── vault_verify ────────────────────────────────────────────────────── */

int vault_verify(vault_ctx_t *ctx,
                 const char *key_name, int key_version,
                 const char *hash_alg, const char *sig_alg,
                 const unsigned char *input, size_t input_len,
                 const unsigned char *sig, size_t sig_len,
                 int *valid_out)
{
    (void)ctx;
    check_expected(key_name);
    check_expected(key_version);
    check_expected(hash_alg);
    check_expected(sig_alg);
    check_expected(input_len);
    check_expected(sig_len);

    *valid_out = mock_type(int);
    return mock_type(int);
}

/* ── stubs for operations not yet exercised by tests ─────────────────── */

int vault_asym_encrypt(vault_ctx_t *ctx, const char *key_name, int key_version,
                       const unsigned char *plaintext, size_t plaintext_len,
                       unsigned char **ciphertext_out, size_t *ciphertext_out_len)
{
    (void)ctx; (void)key_name; (void)key_version;
    (void)plaintext; (void)plaintext_len;
    (void)ciphertext_out; (void)ciphertext_out_len;
    function_called();
    return mock_type(int);
}

int vault_asym_decrypt(vault_ctx_t *ctx, const char *key_name, int key_version,
                       const unsigned char *ciphertext, size_t ciphertext_len,
                       unsigned char **plaintext_out, size_t *plaintext_out_len)
{
    (void)ctx; (void)key_name; (void)key_version;
    (void)ciphertext; (void)ciphertext_len;
    (void)plaintext_out; (void)plaintext_out_len;
    function_called();
    return mock_type(int);
}

int vault_sym_encrypt(vault_ctx_t *ctx, const char *key_name, int key_version,
                      const unsigned char *plaintext, size_t plaintext_len,
                      unsigned char **ciphertext_out, size_t *ciphertext_out_len)
{
    (void)ctx; (void)key_name; (void)key_version;
    (void)plaintext; (void)plaintext_len;
    (void)ciphertext_out; (void)ciphertext_out_len;
    function_called();
    return mock_type(int);
}

int vault_sym_decrypt(vault_ctx_t *ctx, const char *key_name, int key_version,
                      const unsigned char *ciphertext, size_t ciphertext_len,
                      unsigned char **plaintext_out, size_t *plaintext_out_len)
{
    (void)ctx; (void)key_name; (void)key_version;
    (void)ciphertext; (void)ciphertext_len;
    (void)plaintext_out; (void)plaintext_out_len;
    function_called();
    return mock_type(int);
}

int vault_hmac(vault_ctx_t *ctx, const char *key_name, int key_version,
               const char *algorithm,
               const unsigned char *input, size_t input_len,
               unsigned char **hmac_out, size_t *hmac_out_len)
{
    (void)ctx; (void)key_name; (void)key_version; (void)algorithm;
    (void)input; (void)input_len; (void)hmac_out; (void)hmac_out_len;
    function_called();
    return mock_type(int);
}

int vault_hash(vault_ctx_t *ctx, const char *algorithm,
               const unsigned char *input, size_t input_len,
               unsigned char **hash_out, size_t *hash_out_len)
{
    (void)ctx; (void)algorithm; (void)input; (void)input_len;
    (void)hash_out; (void)hash_out_len;
    function_called();
    return mock_type(int);
}

int vault_random(vault_ctx_t *ctx, size_t bytes, unsigned char **random_out)
{
    (void)ctx; (void)bytes; (void)random_out;
    function_called();
    return mock_type(int);
}
