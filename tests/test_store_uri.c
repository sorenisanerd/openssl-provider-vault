#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include "vault_store_uri.h"

/* ── vault_uri_parse — happy paths ───────────────────────────────────── */

static void test_parse_simple(void **state)
{
    (void)state;
    vault_uri_t uri = {0};
    assert_int_equal(0, vault_uri_parse("vault:my-key", &uri));
    assert_string_equal("my-key", uri.key_name);
    assert_int_equal(0, uri.version);
    vault_uri_free(&uri);
}

static void test_parse_with_version(void **state)
{
    (void)state;
    vault_uri_t uri = {0};
    assert_int_equal(0, vault_uri_parse("vault:tenant-rsa-key?version=3", &uri));
    assert_string_equal("tenant-rsa-key", uri.key_name);
    assert_int_equal(3, uri.version);
    vault_uri_free(&uri);
}

static void test_parse_version_1(void **state)
{
    (void)state;
    vault_uri_t uri = {0};
    assert_int_equal(0, vault_uri_parse("vault:my-signing-key?version=1", &uri));
    assert_int_equal(1, uri.version);
    vault_uri_free(&uri);
}

static void test_parse_name_with_hyphens(void **state)
{
    (void)state;
    vault_uri_t uri = {0};
    assert_int_equal(0, vault_uri_parse("vault:prod-rsa-4096-signing", &uri));
    assert_string_equal("prod-rsa-4096-signing", uri.key_name);
    vault_uri_free(&uri);
}

static void test_parse_unknown_query_param_ignored(void **state)
{
    (void)state;
    vault_uri_t uri = {0};
    assert_int_equal(0,
        vault_uri_parse("vault:my-key?version=2&future=param", &uri));
    assert_string_equal("my-key", uri.key_name);
    assert_int_equal(2, uri.version);
    vault_uri_free(&uri);
}

/* ── vault_uri_parse — error cases ───────────────────────────────────── */

static void test_parse_wrong_scheme(void **state)
{
    (void)state;
    vault_uri_t uri = {0};
    assert_int_equal(-1,
        vault_uri_parse("pkcs11:object=mykey;type=private", &uri));
}

static void test_parse_empty_name(void **state)
{
    (void)state;
    vault_uri_t uri = {0};
    assert_int_equal(-1, vault_uri_parse("vault:", &uri));
}

static void test_parse_null(void **state)
{
    (void)state;
    vault_uri_t uri = {0};
    assert_int_equal(-1, vault_uri_parse(NULL, &uri));
}

static void test_parse_plain_string(void **state)
{
    (void)state;
    vault_uri_t uri = {0};
    assert_int_equal(-1, vault_uri_parse("just-a-key-name", &uri));
}

/* ── vault_uri_format ────────────────────────────────────────────────── */

static void test_format_no_version(void **state)
{
    (void)state;
    char *uri = vault_uri_format("my-key", 0);
    assert_non_null(uri);
    assert_string_equal("vault:my-key", uri);
    free(uri);
}

static void test_format_with_version(void **state)
{
    (void)state;
    char *uri = vault_uri_format("my-key", 3);
    assert_non_null(uri);
    assert_string_equal("vault:my-key?version=3", uri);
    free(uri);
}

static void test_format_version_1(void **state)
{
    (void)state;
    char *uri = vault_uri_format("tenant-ec-key", 1);
    assert_non_null(uri);
    assert_string_equal("vault:tenant-ec-key?version=1", uri);
    free(uri);
}

static void test_format_null_name(void **state)
{
    (void)state;
    assert_null(vault_uri_format(NULL, 0));
}

static void test_format_empty_name(void **state)
{
    (void)state;
    assert_null(vault_uri_format("", 0));
}

/* ── roundtrip: format → parse ───────────────────────────────────────── */

static void test_roundtrip_latest(void **state)
{
    (void)state;
    char *formatted = vault_uri_format("prod-signing-key", 0);
    assert_non_null(formatted);

    vault_uri_t parsed = {0};
    assert_int_equal(0, vault_uri_parse(formatted, &parsed));
    assert_string_equal("prod-signing-key", parsed.key_name);
    assert_int_equal(0, parsed.version);

    free(formatted);
    vault_uri_free(&parsed);
}

static void test_roundtrip_pinned_version(void **state)
{
    (void)state;
    char *formatted = vault_uri_format("archive-rsa-key", 5);
    assert_non_null(formatted);

    vault_uri_t parsed = {0};
    assert_int_equal(0, vault_uri_parse(formatted, &parsed));
    assert_string_equal("archive-rsa-key", parsed.key_name);
    assert_int_equal(5, parsed.version);

    free(formatted);
    vault_uri_free(&parsed);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_simple),
        cmocka_unit_test(test_parse_with_version),
        cmocka_unit_test(test_parse_version_1),
        cmocka_unit_test(test_parse_name_with_hyphens),
        cmocka_unit_test(test_parse_unknown_query_param_ignored),

        cmocka_unit_test(test_parse_wrong_scheme),
        cmocka_unit_test(test_parse_empty_name),
        cmocka_unit_test(test_parse_null),
        cmocka_unit_test(test_parse_plain_string),

        cmocka_unit_test(test_format_no_version),
        cmocka_unit_test(test_format_with_version),
        cmocka_unit_test(test_format_version_1),
        cmocka_unit_test(test_format_null_name),
        cmocka_unit_test(test_format_empty_name),

        cmocka_unit_test(test_roundtrip_latest),
        cmocka_unit_test(test_roundtrip_pinned_version),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
