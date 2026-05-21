/*
 * Unit tests for store.c.
 *
 * vault_store_open / _load / _eof / _close are static functions accessed
 * here via the vault_store_funcs OSSL_DISPATCH table so store.c needs no
 * modifications.  vault_type_to_algo is tested indirectly through
 * vault_store_load.
 *
 * All tests use mock_vault_client.c instead of the real vault_client.c.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/core_dispatch.h>   /* OSSL_FUNC_store_* types/accessors */
#include <openssl/core_names.h>      /* OSSL_OBJECT_PARAM_* string constants (3.x) */
#include <openssl/core_object.h>     /* OSSL_OBJECT_PKEY numeric constant */
#include <openssl/params.h>          /* OSSL_PARAM_locate_const, OSSL_PARAM_get_int */
#include <openssl/evp.h>             /* OSSL_LIB_CTX_new/free */

#include "provider.h"
#include "vault_client.h"
#include "vault_keyref.h"

/* ── store dispatch table ─────────────────────────────────────────────── */

extern const OSSL_DISPATCH vault_store_funcs[];

static OSSL_FUNC_store_open_fn  *fn_open;
static OSSL_FUNC_store_load_fn  *fn_load;
static OSSL_FUNC_store_eof_fn   *fn_eof;
static OSSL_FUNC_store_close_fn *fn_close;

/*
 * OSSL_CORE_MAKE_FUNC generates an accessor that returns opf->function
 * directly — it does NOT iterate the table by function_id.  We must find
 * the right entry ourselves before casting.
 */
static void *find_in_dispatch(const OSSL_DISPATCH *table, int id)
{
    for (; table->function_id != 0; table++)
        if (table->function_id == id)
            return (void *)table->function;
    return NULL;
}

static int suite_setup(void **state)
{
    (void)state;
    fn_open  = (OSSL_FUNC_store_open_fn  *)find_in_dispatch(vault_store_funcs, OSSL_FUNC_STORE_OPEN);
    fn_load  = (OSSL_FUNC_store_load_fn  *)find_in_dispatch(vault_store_funcs, OSSL_FUNC_STORE_LOAD);
    fn_eof   = (OSSL_FUNC_store_eof_fn   *)find_in_dispatch(vault_store_funcs, OSSL_FUNC_STORE_EOF);
    fn_close = (OSSL_FUNC_store_close_fn *)find_in_dispatch(vault_store_funcs, OSSL_FUNC_STORE_CLOSE);
    return (fn_open && fn_load && fn_eof && fn_close) ? 0 : -1;
}

/* ── test fixtures ───────────────────────────────────────────────────── */

/* Minimal bytes accepted by vault_keyref_new as pubkey_der. */
static const unsigned char FAKE_DER[]   = { 0x30, 0x03, 0x01, 0x01, 0x00 };
static const size_t        FAKE_DER_LEN = sizeof(FAKE_DER);

static vault_provctx_t *make_provctx(void)
{
    vault_provctx_t *ctx = calloc(1, sizeof(*ctx));
    ctx->libctx = OSSL_LIB_CTX_new();
    /* ctx->vault stays NULL — used for tests that don't reach vault_get_key */
    return ctx;
}

static vault_provctx_t *make_provctx_with_vault(void)
{
    vault_provctx_t *ctx = make_provctx();
    ctx->vault = vault_ctx_new("http://127.0.0.1:8200", "root", NULL);
    return ctx;
}

static void free_provctx(vault_provctx_t *ctx)
{
    OSSL_LIB_CTX_free(ctx->libctx);
    vault_ctx_free(ctx->vault);
    free(ctx);
}

/* ── callback helpers ────────────────────────────────────────────────── */

typedef struct {
    int  called;
    int  obj_type;
    char data_type[64];
} cb_data_t;

static int store_object_cb(const OSSL_PARAM *params, void *cbarg)
{
    cb_data_t *d = (cb_data_t *)cbarg;
    d->called++;

    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_TYPE);
    if (p)
        OSSL_PARAM_get_int(p, &d->obj_type);

    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
    if (p) {
        char *s = d->data_type;
        OSSL_PARAM_get_utf8_string(p, &s, sizeof(d->data_type));
    }

    return 1;
}

/*
 * Callback that deserialises the REFERENCE param to capture the stored
 * key version — used for version-resolution tests.
 */
static int version_capture_cb(const OSSL_PARAM *params, void *cbarg)
{
    int *ver = (int *)cbarg;
    const OSSL_PARAM *p =
        OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
    if (p && p->data && p->data_size > 0) {
        vault_keyref_t *ref =
            vault_keyref_deserialize((const unsigned char *)p->data,
                                      p->data_size);
        if (ref) {
            *ver = ref->key_version;
            vault_keyref_free(ref);
        }
    }
    return 1;
}

/* ── vault_store_open ────────────────────────────────────────────────── */

static void test_open_valid_uri(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    void *ctx = fn_open(provctx, "vault:my-key");
    assert_non_null(ctx);
    fn_close(ctx);
    free_provctx(provctx);
}

static void test_open_wrong_scheme(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    void *ctx = fn_open(provctx, "pkcs11:object=mykey;type=private");
    assert_null(ctx);
    free_provctx(provctx);
}

static void test_open_empty_key_name(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    void *ctx = fn_open(provctx, "vault:");
    assert_null(ctx);
    free_provctx(provctx);
}

static void test_open_null_uri(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    void *ctx = fn_open(provctx, NULL);
    assert_null(ctx);
    free_provctx(provctx);
}

/* ── vault_store_eof ─────────────────────────────────────────────────── */

static void test_eof_before_load(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    void *ctx = fn_open(provctx, "vault:my-key");
    assert_non_null(ctx);
    assert_int_equal(0, fn_eof(ctx));
    fn_close(ctx);
    free_provctx(provctx);
}

static void test_eof_after_load(void **state)
{
    (void)state;
    /* vault=NULL so load returns 0 immediately, but still sets loaded=1. */
    vault_provctx_t *provctx = make_provctx();
    void *ctx = fn_open(provctx, "vault:my-key");
    assert_non_null(ctx);
    fn_load(ctx, store_object_cb, NULL, NULL, NULL);
    assert_int_equal(1, fn_eof(ctx));
    fn_close(ctx);
    free_provctx(provctx);
}

/* ── vault_store_close ───────────────────────────────────────────────── */

static void test_close_frees_context(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();
    void *ctx = fn_open(provctx, "vault:any-key");
    assert_non_null(ctx);
    assert_int_equal(1, fn_close(ctx));
    free_provctx(provctx);
}

static void test_close_null_safe(void **state)
{
    (void)state;
    assert_int_equal(1, fn_close(NULL));
}

/* ── vault_store_load ────────────────────────────────────────────────── */

static void test_load_null_vault(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();   /* vault=NULL */
    void *ctx = fn_open(provctx, "vault:my-key");

    cb_data_t cbd = {0};
    int rv = fn_load(ctx, store_object_cb, &cbd, NULL, NULL);
    assert_int_equal(0, rv);
    assert_int_equal(0, cbd.called);     /* callback must not be invoked */
    assert_int_equal(1, fn_eof(ctx));    /* loaded flag set regardless */

    fn_close(ctx);
    free_provctx(provctx);
}

static void test_load_key_not_found(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx_with_vault();
    void *ctx = fn_open(provctx, "vault:missing-key");

    expect_string(vault_get_key, key_name, "missing-key");
    will_return  (vault_get_key, "rsa-2048");           /* key_type — dequeued but unused */
    will_return  (vault_get_key, (unsigned char *)NULL); /* pubkey_der */
    will_return  (vault_get_key, (size_t)0);             /* der_len */
    will_return  (vault_get_key, 0);                     /* latest_version */
    will_return  (vault_get_key, -1);                    /* error */

    cb_data_t cbd = {0};
    int rv = fn_load(ctx, store_object_cb, &cbd, NULL, NULL);
    assert_int_equal(0, rv);
    assert_int_equal(0, cbd.called);

    fn_close(ctx);
    free_provctx(provctx);
}

static void test_load_rsa_key_calls_callback(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx_with_vault();
    void *ctx = fn_open(provctx, "vault:my-rsa-key");

    expect_string(vault_get_key, key_name, "my-rsa-key");
    will_return  (vault_get_key, "rsa-2048");
    will_return  (vault_get_key, FAKE_DER);
    will_return  (vault_get_key, FAKE_DER_LEN);
    will_return  (vault_get_key, 3);   /* latest_version */
    will_return  (vault_get_key, 0);

    cb_data_t cbd = {0};
    int rv = fn_load(ctx, store_object_cb, &cbd, NULL, NULL);
    assert_int_equal(1, rv);
    assert_int_equal(1, cbd.called);
    assert_string_equal("RSA", cbd.data_type);
    assert_int_equal(OSSL_OBJECT_PKEY, cbd.obj_type);

    fn_close(ctx);
    free_provctx(provctx);
}

static void test_load_ec_key_calls_callback(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx_with_vault();
    void *ctx = fn_open(provctx, "vault:my-ec-key");

    expect_string(vault_get_key, key_name, "my-ec-key");
    will_return  (vault_get_key, "ecdsa-p256");
    will_return  (vault_get_key, FAKE_DER);
    will_return  (vault_get_key, FAKE_DER_LEN);
    will_return  (vault_get_key, 1);
    will_return  (vault_get_key, 0);

    cb_data_t cbd = {0};
    int rv = fn_load(ctx, store_object_cb, &cbd, NULL, NULL);
    assert_int_equal(1, rv);
    assert_int_equal(1, cbd.called);
    assert_string_equal("EC", cbd.data_type);
    assert_int_equal(OSSL_OBJECT_PKEY, cbd.obj_type);

    fn_close(ctx);
    free_provctx(provctx);
}

static void test_load_ed25519_key_calls_callback(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx_with_vault();
    void *ctx = fn_open(provctx, "vault:my-ed25519-key");

    expect_string(vault_get_key, key_name, "my-ed25519-key");
    will_return  (vault_get_key, "ed25519");
    will_return  (vault_get_key, FAKE_DER);
    will_return  (vault_get_key, FAKE_DER_LEN);
    will_return  (vault_get_key, 1);
    will_return  (vault_get_key, 0);

    cb_data_t cbd = {0};
    int rv = fn_load(ctx, store_object_cb, &cbd, NULL, NULL);
    assert_int_equal(1, rv);
    assert_int_equal(1, cbd.called);
    assert_string_equal("ED25519", cbd.data_type);

    fn_close(ctx);
    free_provctx(provctx);
}

static void test_load_ed448_key_calls_callback(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx_with_vault();
    void *ctx = fn_open(provctx, "vault:my-ed448-key");

    expect_string(vault_get_key, key_name, "my-ed448-key");
    will_return  (vault_get_key, "ed448");
    will_return  (vault_get_key, FAKE_DER);
    will_return  (vault_get_key, FAKE_DER_LEN);
    will_return  (vault_get_key, 1);
    will_return  (vault_get_key, 0);

    cb_data_t cbd = {0};
    int rv = fn_load(ctx, store_object_cb, &cbd, NULL, NULL);
    assert_int_equal(1, rv);
    assert_int_equal(1, cbd.called);
    assert_string_equal("ED448", cbd.data_type);

    fn_close(ctx);
    free_provctx(provctx);
}

/* vault_type_to_algo returns NULL for symmetric/HMAC types — no callback. */
static void test_load_symmetric_key_skips_callback(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx_with_vault();
    void *ctx = fn_open(provctx, "vault:my-aes-key");

    expect_string(vault_get_key, key_name, "my-aes-key");
    will_return  (vault_get_key, "aes256-gcm96");
    will_return  (vault_get_key, (unsigned char *)NULL);   /* no public key */
    will_return  (vault_get_key, (size_t)0);
    will_return  (vault_get_key, 1);
    will_return  (vault_get_key, 0);

    cb_data_t cbd = {0};
    int rv = fn_load(ctx, store_object_cb, &cbd, NULL, NULL);
    assert_int_equal(0, rv);
    assert_int_equal(0, cbd.called);   /* callback not invoked for unknown type */

    fn_close(ctx);
    free_provctx(provctx);
}

/* When the URI has no ?version=, vault_store_load uses latest_version. */
static void test_load_uses_latest_version(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx_with_vault();
    void *ctx = fn_open(provctx, "vault:versioned-key");   /* no ?version= */

    expect_string(vault_get_key, key_name, "versioned-key");
    will_return  (vault_get_key, "ecdsa-p384");
    will_return  (vault_get_key, FAKE_DER);
    will_return  (vault_get_key, FAKE_DER_LEN);
    will_return  (vault_get_key, 5);   /* latest_version */
    will_return  (vault_get_key, 0);

    int ver = -1;
    int rv  = fn_load(ctx, version_capture_cb, &ver, NULL, NULL);
    assert_int_equal(1, rv);
    assert_int_equal(5, ver);   /* should reflect latest_version from Vault */

    fn_close(ctx);
    free_provctx(provctx);
}

/* When the URI has ?version=N, that version is stored in the keyref. */
static void test_load_uses_pinned_version(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx_with_vault();
    void *ctx = fn_open(provctx, "vault:pinned-key?version=7");

    expect_string(vault_get_key, key_name, "pinned-key");
    will_return  (vault_get_key, "rsa-2048");
    will_return  (vault_get_key, FAKE_DER);
    will_return  (vault_get_key, FAKE_DER_LEN);
    will_return  (vault_get_key, 10);   /* latest_version — must NOT be used */
    will_return  (vault_get_key, 0);

    int ver = -1;
    int rv  = fn_load(ctx, version_capture_cb, &ver, NULL, NULL);
    assert_int_equal(1, rv);
    assert_int_equal(7, ver);   /* URI version takes priority */

    fn_close(ctx);
    free_provctx(provctx);
}

/* A second call to load must return 0 without touching Vault. */
static void test_load_double_load_is_noop(void **state)
{
    (void)state;
    vault_provctx_t *provctx = make_provctx();   /* vault=NULL */
    void *ctx = fn_open(provctx, "vault:my-key");

    /* First load: vault=NULL → sets loaded=1, returns 0. */
    fn_load(ctx, store_object_cb, NULL, NULL, NULL);
    assert_int_equal(1, fn_eof(ctx));

    /* Second load: already loaded → returns 0, no mock expectations consumed. */
    int rv = fn_load(ctx, store_object_cb, NULL, NULL, NULL);
    assert_int_equal(0, rv);

    fn_close(ctx);
    free_provctx(provctx);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* vault_store_open */
        cmocka_unit_test(test_open_valid_uri),
        cmocka_unit_test(test_open_wrong_scheme),
        cmocka_unit_test(test_open_empty_key_name),
        cmocka_unit_test(test_open_null_uri),

        /* vault_store_eof */
        cmocka_unit_test(test_eof_before_load),
        cmocka_unit_test(test_eof_after_load),

        /* vault_store_close */
        cmocka_unit_test(test_close_frees_context),
        cmocka_unit_test(test_close_null_safe),

        /* vault_store_load (exercises vault_type_to_algo indirectly) */
        cmocka_unit_test(test_load_null_vault),
        cmocka_unit_test(test_load_key_not_found),
        cmocka_unit_test(test_load_rsa_key_calls_callback),
        cmocka_unit_test(test_load_ec_key_calls_callback),
        cmocka_unit_test(test_load_ed25519_key_calls_callback),
        cmocka_unit_test(test_load_ed448_key_calls_callback),
        cmocka_unit_test(test_load_symmetric_key_skips_callback),
        cmocka_unit_test(test_load_uses_latest_version),
        cmocka_unit_test(test_load_uses_pinned_version),
        cmocka_unit_test(test_load_double_load_is_noop),
    };
    return cmocka_run_group_tests(tests, suite_setup, NULL);
}
