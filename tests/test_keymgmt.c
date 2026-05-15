#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include "provider.h"
#include "vault_keyref.h"
#include "keymgmt.h"

/* ── test fixtures ───────────────────────────────────────────────────── */

static const unsigned char FAKE_DER[] = {
    0x30, 0x59, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
};
static const size_t FAKE_DER_LEN = sizeof(FAKE_DER);

static vault_provctx_t *make_provctx(void)
{
    vault_provctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->libctx = OSSL_LIB_CTX_new();
    /* ctx->vault is NULL — tests use mock_vault_client which ignores it */
    return ctx;
}

static void free_provctx(vault_provctx_t *ctx)
{
    OSSL_LIB_CTX_free(ctx->libctx);
    free(ctx);
}

/* Serialise a ready-made keyref so we can pass it to keymgmt_load(). */
static unsigned char *make_ref_bytes(const char *name, int version,
                                      const char *type, size_t *len_out)
{
    vault_keyref_t *ref = vault_keyref_new(name, version, type,
                                            FAKE_DER, FAKE_DER_LEN);
    unsigned char *bytes = NULL;
    vault_keyref_serialize(ref, &bytes, len_out);
    vault_keyref_free(ref);
    return bytes;
}

/* ── keymgmt_load ────────────────────────────────────────────────────── */

static void test_load_returns_keyref(void **state)
{
    (void)state;
    size_t len;
    unsigned char *bytes = make_ref_bytes("my-rsa-key", 0, "rsa-2048", &len);

    vault_keyref_t *key = vault_keymgmt_load(bytes, len);
    assert_non_null(key);
    assert_string_equal("my-rsa-key", key->key_name);
    assert_string_equal("rsa-2048",   key->key_type);
    assert_int_equal(0,               key->key_version);

    vault_keymgmt_free(key);
    free(bytes);
}

static void test_load_preserves_pubkey(void **state)
{
    (void)state;
    size_t len;
    unsigned char *bytes = make_ref_bytes("ec-key", 2, "ecdsa-p256", &len);

    vault_keyref_t *key = vault_keymgmt_load(bytes, len);
    assert_non_null(key);
    assert_int_equal(FAKE_DER_LEN, key->pubkey_der_len);
    assert_memory_equal(FAKE_DER, key->pubkey_der, FAKE_DER_LEN);
    assert_int_equal(2, key->key_version);

    vault_keymgmt_free(key);
    free(bytes);
}

static void test_load_null_returns_null(void **state)
{
    (void)state;
    assert_null(vault_keymgmt_load(NULL, 0));
}

static void test_load_truncated_returns_null(void **state)
{
    (void)state;
    unsigned char bad[4] = {0x00, 0x00, 0x00, 0x40}; /* name_len=64 but nothing follows */
    assert_null(vault_keymgmt_load(bad, sizeof(bad)));
}

/* ── keymgmt_has ─────────────────────────────────────────────────────── */

static void test_has_public_key_true(void **state)
{
    (void)state;
    size_t len;
    unsigned char *bytes = make_ref_bytes("my-key", 0, "rsa-2048", &len);
    vault_keyref_t *key  = vault_keymgmt_load(bytes, len);

    assert_int_equal(1,
        vault_keymgmt_has(key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY));

    vault_keymgmt_free(key);
    free(bytes);
}

static void test_has_private_key_true_when_named(void **state)
{
    (void)state;
    size_t len;
    unsigned char *bytes = make_ref_bytes("my-key", 0, "rsa-2048", &len);
    vault_keyref_t *key  = vault_keymgmt_load(bytes, len);

    /* Private key lives in Vault — has() must return 1 so sign works. */
    assert_int_equal(1,
        vault_keymgmt_has(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY));

    vault_keymgmt_free(key);
    free(bytes);
}

static void test_has_public_key_false_when_no_der(void **state)
{
    (void)state;
    /* Keyref without public key (e.g. HMAC key — public part irrelevant). */
    vault_keyref_t *ref = vault_keyref_new("hmac-key", 0, "hmac", NULL, 0);
    assert_int_equal(0,
        vault_keymgmt_has(ref, OSSL_KEYMGMT_SELECT_PUBLIC_KEY));
    vault_keymgmt_free(ref);
}

static void test_has_null_keydata_false(void **state)
{
    (void)state;
    assert_int_equal(0,
        vault_keymgmt_has(NULL, OSSL_KEYMGMT_SELECT_PUBLIC_KEY));
}

/* ── keymgmt_gen — RSA ───────────────────────────────────────────────── */

static void test_gen_rsa_2048(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();

    /* Set up mock expectations for vault_create_key + vault_get_key. */
    expect_string(vault_create_key, key_name, "new-rsa-key");
    expect_string(vault_create_key, key_type,  "rsa-2048");
    expect_value (vault_create_key, exportable, 0);
    will_return  (vault_create_key, 0);   /* success */

    expect_string     (vault_get_key, key_name, "new-rsa-key");
    will_return       (vault_get_key, "rsa-2048");
    will_return       (vault_get_key, FAKE_DER);
    will_return       (vault_get_key, FAKE_DER_LEN);
    will_return       (vault_get_key, 1);  /* latest_version */
    will_return       (vault_get_key, 0);  /* return code */

    /* Build gen params. */
    unsigned int bits = 2048;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("vault-key-name", "new-rsa-key", 0),
        OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits),
        OSSL_PARAM_construct_end()
    };

    void *genctx = vault_keymgmt_gen_init(provctx,
                                           OSSL_KEYMGMT_SELECT_KEYPAIR,
                                           params);
    assert_non_null(genctx);

    /* Set pkey_type directly via the known internal layout.
     * This will go away once per-key-type dispatch tables are wired up. */
    typedef struct { vault_provctx_t *provctx; int pkey_type; int bits;
                     int curve_nid; char *key_name; int exportable; }
        genctx_t;
    ((genctx_t *)genctx)->pkey_type = EVP_PKEY_RSA;

    vault_keyref_t *key = vault_keymgmt_gen(genctx, NULL, NULL);
    assert_non_null(key);
    assert_string_equal("new-rsa-key", key->key_name);
    assert_string_equal("rsa-2048",    key->key_type);
    assert_int_equal(1,                key->key_version);
    assert_int_equal(FAKE_DER_LEN,     key->pubkey_der_len);

    vault_keymgmt_gen_cleanup(genctx);
    vault_keymgmt_free(key);
    free_provctx(provctx);
}

static void test_gen_missing_key_name_fails(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();

    /* No vault-key-name param supplied. */
    OSSL_PARAM params[] = { OSSL_PARAM_construct_end() };
    void *genctx = vault_keymgmt_gen_init(provctx,
                                           OSSL_KEYMGMT_SELECT_KEYPAIR,
                                           params);
    assert_non_null(genctx);

    /* gen() must fail without a key name — no mock calls expected. */
    vault_keyref_t *key = vault_keymgmt_gen(genctx, NULL, NULL);
    assert_null(key);

    vault_keymgmt_gen_cleanup(genctx);
    free_provctx(provctx);
}

static void test_gen_vault_error_propagates(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();

    expect_string(vault_create_key, key_name,   "bad-key");
    expect_string(vault_create_key, key_type,    "ecdsa-p256");
    expect_value (vault_create_key, exportable,  0);
    will_return  (vault_create_key, -1);  /* Vault returns an error */

    unsigned int bits = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("vault-key-name", "bad-key", 0),
        OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits),
        OSSL_PARAM_construct_end()
    };
    void *genctx = vault_keymgmt_gen_init(provctx,
                                           OSSL_KEYMGMT_SELECT_KEYPAIR,
                                           params);
    typedef struct { vault_provctx_t *provctx; int pkey_type; int bits;
                     int curve_nid; char *key_name; int exportable; }
        genctx_t;
    ((genctx_t *)genctx)->pkey_type  = EVP_PKEY_EC;
    ((genctx_t *)genctx)->curve_nid  = NID_X9_62_prime256v1;

    vault_keyref_t *key = vault_keymgmt_gen(genctx, NULL, NULL);
    assert_null(key);   /* error from Vault must surface as NULL */

    vault_keymgmt_gen_cleanup(genctx);
    free_provctx(provctx);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_load_returns_keyref),
        cmocka_unit_test(test_load_preserves_pubkey),
        cmocka_unit_test(test_load_null_returns_null),
        cmocka_unit_test(test_load_truncated_returns_null),

        cmocka_unit_test(test_has_public_key_true),
        cmocka_unit_test(test_has_private_key_true_when_named),
        cmocka_unit_test(test_has_public_key_false_when_no_der),
        cmocka_unit_test(test_has_null_keydata_false),

        cmocka_unit_test(test_gen_rsa_2048),
        cmocka_unit_test(test_gen_missing_key_name_fails),
        cmocka_unit_test(test_gen_vault_error_propagates),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
