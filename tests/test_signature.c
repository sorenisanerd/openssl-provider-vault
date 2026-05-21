#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "provider.h"
#include "vault_keyref.h"
#include "signature.h"
#include "wrap_malloc.h"

/* ── test fixtures ───────────────────────────────────────────────────── */

/* Simulated SHA-256 digest — 32 zero bytes is fine for mock tests. */
static const unsigned char DIGEST_SHA256[32] = {0};

/* Fake DER signature bytes returned by the mock. */
static const unsigned char FAKE_RSA_SIG[256] = {0xaa};
static const unsigned char FAKE_EC_SIG[72]   = {0xbb};

static vault_provctx_t *make_provctx(void)
{
    vault_provctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->libctx = OSSL_LIB_CTX_new();
    return ctx;
}

static void free_provctx(vault_provctx_t *ctx)
{
    OSSL_LIB_CTX_free(ctx->libctx);
    free(ctx);
}

static vault_keyref_t *make_rsa_key(void)
{
    return vault_keyref_new("my-rsa-key", 0, "rsa-2048", NULL, 0);
}

static vault_keyref_t *make_ec_key(void)
{
    return vault_keyref_new("my-ec-key", 2, "ecdsa-p256", NULL, 0);
}

/* ── sign: RSA-PSS with SHA-256 ──────────────────────────────────────── */

static void test_sign_rsa_pss_sha256(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();

    void *sigctx = vault_sig_newctx(provctx, NULL);
    assert_non_null(sigctx);

    /* init with RSA-PSS / SHA-256 params */
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                          "SHA256", 0),
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                          "pss", 0),
        OSSL_PARAM_construct_end()
    };
    assert_int_equal(1, vault_sig_sign_init(sigctx, key, params));

    /* Expect the mock to receive exactly these arguments. */
    expect_string(vault_sign, key_name,    "my-rsa-key");
    expect_value (vault_sign, key_version, 0);
    expect_string(vault_sign, hash_alg,    "sha2-256");
    expect_string(vault_sign, sig_alg,     "pss");
    expect_value (vault_sign, input_len,   32);   /* SHA-256 digest size */
    will_return  (vault_sign, FAKE_RSA_SIG);
    will_return  (vault_sign, (size_t)256);
    will_return  (vault_sign, 0);   /* success */

    unsigned char sig[512];
    size_t siglen = 0;
    assert_int_equal(1,
        vault_sig_sign(sigctx, sig, &siglen, sizeof(sig),
                       DIGEST_SHA256, sizeof(DIGEST_SHA256)));
    assert_int_equal(256, siglen);
    assert_memory_equal(FAKE_RSA_SIG, sig, 256);

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

static void test_sign_rsa_pkcs1v15_sha256(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();

    void *sigctx = vault_sig_newctx(provctx, NULL);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                          "SHA256", 0),
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                          "pkcs1v15", 0),
        OSSL_PARAM_construct_end()
    };
    assert_int_equal(1, vault_sig_sign_init(sigctx, key, params));

    expect_string(vault_sign, key_name,    "my-rsa-key");
    expect_value (vault_sign, key_version, 0);
    expect_string(vault_sign, hash_alg,    "sha2-256");
    expect_string(vault_sign, sig_alg,     "pkcs1v15");  /* not PSS */
    expect_value (vault_sign, input_len,   32);
    will_return  (vault_sign, FAKE_RSA_SIG);
    will_return  (vault_sign, (size_t)256);
    will_return  (vault_sign, 0);

    unsigned char sig[512];
    size_t siglen = 0;
    assert_int_equal(1,
        vault_sig_sign(sigctx, sig, &siglen, sizeof(sig),
                       DIGEST_SHA256, sizeof(DIGEST_SHA256)));

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

/* ── sign: ECDSA with SHA-384 ────────────────────────────────────────── */

static void test_sign_ecdsa_sha384(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_ec_key();

    void *sigctx = vault_sig_newctx(provctx, NULL);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                          "SHA384", 0),
        OSSL_PARAM_construct_end()
    };
    assert_int_equal(1, vault_sig_sign_init(sigctx, key, params));

    /* SHA-384 digest is 48 bytes. */
    unsigned char digest[48] = {0};

    expect_string(vault_sign, key_name,    "my-ec-key");
    expect_value (vault_sign, key_version, 2);
    expect_string(vault_sign, hash_alg,    "sha2-384");
    expect_string(vault_sign, sig_alg,     "pss");   /* default — irrelevant for EC */
    expect_value (vault_sign, input_len,   48);
    will_return  (vault_sign, FAKE_EC_SIG);
    will_return  (vault_sign, (size_t)72);
    will_return  (vault_sign, 0);

    unsigned char sig[128];
    size_t siglen = 0;
    assert_int_equal(1,
        vault_sig_sign(sigctx, sig, &siglen, sizeof(sig),
                       digest, sizeof(digest)));
    assert_int_equal(72, siglen);

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

/* ── sign: size query (sig == NULL) ──────────────────────────────────── */

static void test_sign_size_query(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();
    void *sigctx = vault_sig_newctx(provctx, NULL);

    OSSL_PARAM params[] = { OSSL_PARAM_construct_end() };
    vault_sig_sign_init(sigctx, key, params);

    /* When sig==NULL the function should query Vault for the size and
     * return it in *siglen without copying bytes. */
    expect_string(vault_sign, key_name,    "my-rsa-key");
    expect_value (vault_sign, key_version, 0);
    expect_string(vault_sign, hash_alg,    "sha2-256");
    expect_string(vault_sign, sig_alg,     "pss");
    expect_value (vault_sign, input_len,   32);
    will_return  (vault_sign, FAKE_RSA_SIG);
    will_return  (vault_sign, (size_t)256);
    will_return  (vault_sign, 0);

    size_t siglen = 0;
    assert_int_equal(1,
        vault_sig_sign(sigctx, NULL, &siglen, 0,
                       DIGEST_SHA256, sizeof(DIGEST_SHA256)));
    assert_int_equal(256, siglen);

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

/* ── digest sign: hashes streamed input before asking Vault to sign ──── */

static void test_digest_sign_rsa_pkcs1v15_sha256(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();
    void *sigctx = vault_sig_newctx(provctx, NULL);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                          "pkcs1v15", 0),
        OSSL_PARAM_construct_end()
    };
    assert_int_equal(1,
        vault_sig_digest_sign_init(sigctx, "SHA256", key, params));
    assert_int_equal(1,
        vault_sig_digest_sign_update(sigctx,
                                     (const unsigned char *)"hello ", 6));
    assert_int_equal(1,
        vault_sig_digest_sign_update(sigctx,
                                     (const unsigned char *)"csr", 3));

    expect_string(vault_sign, key_name,    "my-rsa-key");
    expect_value (vault_sign, key_version, 0);
    expect_string(vault_sign, hash_alg,    "sha2-256");
    expect_string(vault_sign, sig_alg,     "pkcs1v15");
    expect_value (vault_sign, input_len,   32);
    will_return  (vault_sign, FAKE_RSA_SIG);
    will_return  (vault_sign, (size_t)256);
    will_return  (vault_sign, 0);

    unsigned char sig[512];
    size_t siglen = 0;
    assert_int_equal(1,
        vault_sig_digest_sign_final(sigctx, sig, &siglen, sizeof(sig)));
    assert_int_equal(256, siglen);
    assert_memory_equal(FAKE_RSA_SIG, sig, 256);

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

static void test_digest_sign_default_rsa_uses_pkcs1v15_and_algorithm_id(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();
    void *sigctx = vault_sig_newctx(provctx, NULL);

    OSSL_PARAM init_params[] = { OSSL_PARAM_construct_end() };
    assert_int_equal(1,
        vault_sig_digest_sign_init(sigctx, "SHA256", key, init_params));

    char pad_mode[32] = {0};
    unsigned char aid[128] = {0};
    OSSL_PARAM get_params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                          pad_mode, sizeof(pad_mode)),
        OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
                                           aid, sizeof(aid)),
        OSSL_PARAM_construct_end()
    };
    assert_int_equal(1, vault_sig_get_ctx_params(sigctx, get_params));
    assert_string_equal("pkcs1v15", pad_mode);
    assert_true(get_params[1].return_size > 0);

    const unsigned char *p = aid;
    X509_ALGOR *alg = d2i_X509_ALGOR(NULL, &p, get_params[1].return_size);
    assert_non_null(alg);
    int alg_nid = OBJ_obj2nid(alg->algorithm);
    assert_int_equal(NID_sha256WithRSAEncryption, alg_nid);
    X509_ALGOR_free(alg);

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

/* ── sign: vault error propagates ────────────────────────────────────── */

static void test_sign_vault_error(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();
    void *sigctx = vault_sig_newctx(provctx, NULL);

    OSSL_PARAM params[] = { OSSL_PARAM_construct_end() };
    vault_sig_sign_init(sigctx, key, params);

    expect_any  (vault_sign, key_name);
    expect_any  (vault_sign, key_version);
    expect_any  (vault_sign, hash_alg);
    expect_any  (vault_sign, sig_alg);
    expect_any  (vault_sign, input_len);
    will_return (vault_sign, NULL);
    will_return (vault_sign, (size_t)0);
    will_return (vault_sign, -1);   /* Vault error */

    unsigned char sig[512];
    size_t siglen = 0;
    assert_int_equal(0,
        vault_sig_sign(sigctx, sig, &siglen, sizeof(sig),
                       DIGEST_SHA256, sizeof(DIGEST_SHA256)));

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

/* ── verify: valid signature ─────────────────────────────────────────── */

static void test_verify_valid(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();
    void *sigctx = vault_sig_newctx(provctx, NULL);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                          "SHA256", 0),
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                          "pss", 0),
        OSSL_PARAM_construct_end()
    };
    vault_sig_verify_init(sigctx, key, params);

    expect_string(vault_verify, key_name,    "my-rsa-key");
    expect_value (vault_verify, key_version, 0);
    expect_string(vault_verify, hash_alg,    "sha2-256");
    expect_string(vault_verify, sig_alg,     "pss");
    expect_value (vault_verify, input_len,   32);
    expect_value (vault_verify, sig_len,     256);
    will_return  (vault_verify, 1);    /* valid = true */
    will_return  (vault_verify, 0);    /* return code = success */

    assert_int_equal(1,
        vault_sig_verify(sigctx,
                         FAKE_RSA_SIG, 256,
                         DIGEST_SHA256, sizeof(DIGEST_SHA256)));

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

static void test_verify_invalid_signature(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();
    void *sigctx = vault_sig_newctx(provctx, NULL);

    OSSL_PARAM params[] = { OSSL_PARAM_construct_end() };
    vault_sig_verify_init(sigctx, key, params);

    expect_any(vault_verify, key_name);
    expect_any(vault_verify, key_version);
    expect_any(vault_verify, hash_alg);
    expect_any(vault_verify, sig_alg);
    expect_any(vault_verify, input_len);
    expect_any(vault_verify, sig_len);
    will_return(vault_verify, 0);    /* valid = false */
    will_return(vault_verify, 0);    /* return code = success (not a network err) */

    assert_int_equal(0,
        vault_sig_verify(sigctx,
                         FAKE_RSA_SIG, 256,
                         DIGEST_SHA256, sizeof(DIGEST_SHA256)));

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

/* ── params: get/set roundtrip ───────────────────────────────────────── */

static void test_get_ctx_params(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    void *sigctx = vault_sig_newctx(provctx, NULL);

    /* Set params. */
    OSSL_PARAM set_params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                          "SHA512", 0),
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                          "pkcs1v15", 0),
        OSSL_PARAM_construct_end()
    };
    assert_int_equal(1, vault_sig_set_ctx_params(sigctx, set_params));

    /* Read them back. */
    char digest_buf[64]  = {0};
    char mode_buf[32]    = {0};
    OSSL_PARAM get_params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                          digest_buf, sizeof(digest_buf)),
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                          mode_buf, sizeof(mode_buf)),
        OSSL_PARAM_construct_end()
    };
    assert_int_equal(1, vault_sig_get_ctx_params(sigctx, get_params));
    /* OBJ_nid2sn(NID_sha512) returns "SHA512" */
    assert_string_equal("SHA512",   digest_buf);
    assert_string_equal("pkcs1v15", mode_buf);

    vault_sig_freectx(sigctx);
    free_provctx(provctx);
}

/* ── dupctx ──────────────────────────────────────────────────────────── */

static void test_dupctx(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();
    void *sigctx = vault_sig_newctx(provctx, NULL);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                          "pkcs1v15", 0),
        OSSL_PARAM_construct_end()
    };
    vault_sig_sign_init(sigctx, key, params);

    void *dup = vault_sig_dupctx(sigctx);
    assert_non_null(dup);
    assert_ptr_not_equal(sigctx, dup);

    /* Both should sign identically — set up two mock calls. */
    for (int i = 0; i < 2; i++) {
        expect_any(vault_sign, key_name);
        expect_any(vault_sign, key_version);
        expect_any(vault_sign, hash_alg);
        expect_string(vault_sign, sig_alg, "pkcs1v15");
        expect_any  (vault_sign, input_len);
        will_return (vault_sign, FAKE_RSA_SIG);
        will_return (vault_sign, (size_t)256);
        will_return (vault_sign, 0);
    }

    unsigned char sig1[512], sig2[512];
    size_t len1 = 0, len2 = 0;
    vault_sig_sign(sigctx, sig1, &len1, sizeof(sig1),
                   DIGEST_SHA256, sizeof(DIGEST_SHA256));
    vault_sig_sign(dup,    sig2, &len2, sizeof(sig2),
                   DIGEST_SHA256, sizeof(DIGEST_SHA256));

    assert_int_equal(len1, len2);
    assert_memory_equal(sig1, sig2, len1);

    vault_sig_freectx(sigctx);
    vault_sig_freectx(dup);
    vault_keyref_free(key);
    free_provctx(provctx);
}

/* ── dupctx: copies a live mdctx (populated by digest_sign_init+update) ─ */

static void test_dupctx_with_mdctx(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();
    void *sigctx = vault_sig_newctx(provctx, NULL);

    /* digest_sign_init allocates and initialises mdctx. */
    OSSL_PARAM params[] = { OSSL_PARAM_construct_end() };
    assert_int_equal(1,
        vault_sig_digest_sign_init(sigctx, "SHA256", key, params));

    assert_int_equal(1,
        vault_sig_digest_sign_update(sigctx,
                                     (const unsigned char *)"hello", 5));

    /*
     * Dup the context while mdctx is non-null and has accumulated state.
     * vault_sig_dupctx must call EVP_MD_CTX_copy_ex — the branch under test.
     */
    void *dup = vault_sig_dupctx(sigctx);
    assert_non_null(dup);
    assert_ptr_not_equal(sigctx, dup);

    /*
     * Both contexts hold a copy of the same in-progress SHA-256 state over
     * "hello".  Finalising each independently should pass the same 32-byte
     * digest to vault_sign (pkcs1v15 — RSA default when no pad mode param).
     */
    for (int i = 0; i < 2; i++) {
        expect_string(vault_sign, key_name,    "my-rsa-key");
        expect_value (vault_sign, key_version, 0);
        expect_string(vault_sign, hash_alg,    "sha2-256");
        expect_string(vault_sign, sig_alg,     "pkcs1v15");
        expect_value (vault_sign, input_len,   32);
        will_return  (vault_sign, FAKE_RSA_SIG);
        will_return  (vault_sign, (size_t)256);
        will_return  (vault_sign, 0);
    }

    unsigned char sig1[512], sig2[512];
    size_t len1 = 0, len2 = 0;
    assert_int_equal(1,
        vault_sig_digest_sign_final(sigctx, sig1, &len1, sizeof(sig1)));
    assert_int_equal(1,
        vault_sig_digest_sign_final(dup,    sig2, &len2, sizeof(sig2)));

    assert_int_equal(256, len1);
    assert_int_equal(256, len2);
    assert_memory_equal(sig1, sig2, 256);   /* same digest → same fake sig */

    vault_sig_freectx(sigctx);
    vault_sig_freectx(dup);
    vault_keyref_free(key);
    free_provctx(provctx);
}

/* ── sign: Ed25519 ───────────────────────────────────────────────────── */

static vault_keyref_t *make_ed25519_key(void)
{
    return vault_keyref_new("my-ed25519-key", 0, "ed25519", NULL, 0);
}

static void test_sign_ed25519(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_ed25519_key();

    void *sigctx = vault_sig_newctx(provctx, NULL);
    assert_non_null(sigctx);

    /* No special params — use the context defaults (sha2-256 / pss). */
    OSSL_PARAM params[] = { OSSL_PARAM_construct_end() };
    assert_int_equal(1, vault_sig_sign_init(sigctx, key, params));

    static const unsigned char FAKE_ED_SIG[64] = {0xcc};

    expect_string(vault_sign, key_name,    "my-ed25519-key");
    expect_value (vault_sign, key_version, 0);
    expect_string(vault_sign, hash_alg,    "sha2-256");   /* default */
    expect_string(vault_sign, sig_alg,     "pss");         /* default */
    expect_value (vault_sign, input_len,   32);            /* SHA-256 digest */
    will_return  (vault_sign, FAKE_ED_SIG);
    will_return  (vault_sign, (size_t)64);
    will_return  (vault_sign, 0);

    unsigned char sig[128];
    size_t siglen = 0;
    assert_int_equal(1,
        vault_sig_sign(sigctx, sig, &siglen, sizeof(sig),
                       DIGEST_SHA256, sizeof(DIGEST_SHA256)));
    assert_int_equal(64, siglen);
    assert_memory_equal(FAKE_ED_SIG, sig, 64);

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

/* ── OOM tests ───────────────────────────────────────────────────────── */

static void test_oom_sig_newctx(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();

    wrap_malloc_fail_after(0);   /* calloc for vault_sigctx_t */
    void *sigctx = vault_sig_newctx(provctx, NULL);
    assert_null(sigctx);

    free_provctx(provctx);
}

static void test_oom_sig_dupctx(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    vault_keyref_t  *key     = make_rsa_key();
    void *sigctx = vault_sig_newctx(provctx, NULL);
    assert_non_null(sigctx);

    OSSL_PARAM params[] = { OSSL_PARAM_construct_end() };
    vault_sig_sign_init(sigctx, key, params);

    wrap_malloc_fail_after(0);   /* malloc for the duplicate vault_sigctx_t */
    void *dup = vault_sig_dupctx(sigctx);
    assert_null(dup);

    vault_sig_freectx(sigctx);
    vault_keyref_free(key);
    free_provctx(provctx);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sign_rsa_pss_sha256),
        cmocka_unit_test(test_sign_rsa_pkcs1v15_sha256),
        cmocka_unit_test(test_sign_ecdsa_sha384),
        cmocka_unit_test(test_sign_size_query),
        cmocka_unit_test(test_digest_sign_rsa_pkcs1v15_sha256),
        cmocka_unit_test(test_digest_sign_default_rsa_uses_pkcs1v15_and_algorithm_id),
        cmocka_unit_test(test_sign_vault_error),

        cmocka_unit_test(test_verify_valid),
        cmocka_unit_test(test_verify_invalid_signature),

        cmocka_unit_test(test_get_ctx_params),
        cmocka_unit_test(test_dupctx),
        cmocka_unit_test(test_dupctx_with_mdctx),

        cmocka_unit_test(test_sign_ed25519),

        cmocka_unit_test(test_oom_sig_newctx),
        cmocka_unit_test(test_oom_sig_dupctx),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
