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

#include "vault_keyref.h"
#include "wrap_malloc.h"

static const unsigned char FAKE_DER[] = {
    0x30, 0x82, 0x01, 0x22,   /* minimal DER header stand-in */
    0xde, 0xad, 0xbe, 0xef,
};
static const size_t FAKE_DER_LEN = sizeof(FAKE_DER);

/* ── vault_keyref_new / free ─────────────────────────────────────────── */

static void test_new_basic(void **state)
{
    (void)state;
    vault_keyref_t *ref = vault_keyref_new("my-key", 0, "rsa-2048",
                                            FAKE_DER, FAKE_DER_LEN);
    assert_non_null(ref);
    assert_string_equal("my-key",   ref->key_name);
    assert_int_equal(0,             ref->key_version);
    assert_string_equal("rsa-2048", ref->key_type);
    assert_int_equal(FAKE_DER_LEN,  ref->pubkey_der_len);
    assert_memory_equal(FAKE_DER,   ref->pubkey_der, FAKE_DER_LEN);
    vault_keyref_free(ref);
}

static void test_new_with_version(void **state)
{
    (void)state;
    vault_keyref_t *ref = vault_keyref_new("tenant-key", 3, "ecdsa-p256",
                                            NULL, 0);
    assert_non_null(ref);
    assert_int_equal(3, ref->key_version);
    assert_null(ref->pubkey_der);
    assert_int_equal(0, ref->pubkey_der_len);
    vault_keyref_free(ref);
}

static void test_new_null_name_fails(void **state)
{
    (void)state;
    assert_null(vault_keyref_new(NULL, 0, "rsa-2048", NULL, 0));
}

static void test_new_null_type_fails(void **state)
{
    (void)state;
    assert_null(vault_keyref_new("my-key", 0, NULL, NULL, 0));
}

static void test_free_null_is_safe(void **state)
{
    (void)state;
    vault_keyref_free(NULL);   /* must not crash */
}

/* ── serialize / deserialize roundtrip ──────────────────────────────── */

static void test_roundtrip_with_pubkey(void **state)
{
    (void)state;
    vault_keyref_t *orig = vault_keyref_new("signing-key", 2, "ecdsa-p384",
                                             FAKE_DER, FAKE_DER_LEN);
    assert_non_null(orig);

    unsigned char *bytes = NULL;
    size_t bytes_len = 0;
    assert_int_equal(0, vault_keyref_serialize(orig, &bytes, &bytes_len));
    assert_non_null(bytes);
    assert_true(bytes_len > 0);

    vault_keyref_t *copy = vault_keyref_deserialize(bytes, bytes_len);
    assert_non_null(copy);

    assert_string_equal(orig->key_name,  copy->key_name);
    assert_int_equal(orig->key_version,  copy->key_version);
    assert_string_equal(orig->key_type,  copy->key_type);
    assert_int_equal(orig->pubkey_der_len, copy->pubkey_der_len);
    assert_memory_equal(orig->pubkey_der, copy->pubkey_der,
                        orig->pubkey_der_len);

    free(bytes);
    vault_keyref_free(orig);
    vault_keyref_free(copy);
}

static void test_roundtrip_no_pubkey(void **state)
{
    (void)state;
    vault_keyref_t *orig = vault_keyref_new("hmac-key", 0, "hmac",
                                             NULL, 0);
    assert_non_null(orig);

    unsigned char *bytes = NULL;
    size_t bytes_len = 0;
    assert_int_equal(0, vault_keyref_serialize(orig, &bytes, &bytes_len));

    vault_keyref_t *copy = vault_keyref_deserialize(bytes, bytes_len);
    assert_non_null(copy);
    assert_null(copy->pubkey_der);
    assert_int_equal(0, copy->pubkey_der_len);
    assert_string_equal("hmac-key", copy->key_name);

    free(bytes);
    vault_keyref_free(orig);
    vault_keyref_free(copy);
}

static void test_roundtrip_version_preserved(void **state)
{
    (void)state;
    vault_keyref_t *orig = vault_keyref_new("rsa-key", 7, "rsa-4096",
                                             FAKE_DER, FAKE_DER_LEN);
    assert_non_null(orig);

    unsigned char *bytes = NULL;
    size_t bytes_len = 0;
    assert_int_equal(0, vault_keyref_serialize(orig, &bytes, &bytes_len));

    vault_keyref_t *copy = vault_keyref_deserialize(bytes, bytes_len);
    assert_non_null(copy);
    assert_int_equal(7, copy->key_version);

    free(bytes);
    vault_keyref_free(orig);
    vault_keyref_free(copy);
}

/* ── deserialize error cases ─────────────────────────────────────────── */

static void test_deserialize_null(void **state)
{
    (void)state;
    assert_null(vault_keyref_deserialize(NULL, 0));
}

static void test_deserialize_empty(void **state)
{
    (void)state;
    unsigned char buf[1] = {0};
    assert_null(vault_keyref_deserialize(buf, 0));
}

static void test_deserialize_truncated(void **state)
{
    (void)state;
    /* Claim name_len=16 but only supply 4 bytes total — must not crash. */
    unsigned char buf[8] = {0x00, 0x00, 0x00, 0x10, 0x41, 0x41, 0x41, 0x41};
    assert_null(vault_keyref_deserialize(buf, sizeof(buf)));
}

/* ── serialize error cases ───────────────────────────────────────────── */

static void test_serialize_null(void **state)
{
    (void)state;
    unsigned char *bytes = NULL;
    size_t len = 0;
    assert_int_equal(-1, vault_keyref_serialize(NULL, &bytes, &len));
}

/* ── OOM tests ───────────────────────────────────────────────────────── */

static void test_oom_keyref_new(void **state)
{
    (void)state;
    wrap_malloc_fail_after(0);   /* calloc for the vault_keyref_t struct */
    vault_keyref_t *ref = vault_keyref_new("k", 0, "rsa-2048", NULL, 0);
    assert_null(ref);
}

static void test_oom_keyref_serialize(void **state)
{
    (void)state;
    vault_keyref_t *ref = vault_keyref_new("k", 0, "rsa-2048", NULL, 0);
    assert_non_null(ref);

    unsigned char *bytes = NULL;
    size_t len = 0;
    wrap_malloc_fail_after(0);   /* malloc(total) for the serialized buffer */
    int rc = vault_keyref_serialize(ref, &bytes, &len);
    assert_int_equal(-1, rc);
    assert_null(bytes);

    vault_keyref_free(ref);
}

static void test_oom_keyref_deserialize_key_name(void **state)
{
    (void)state;
    vault_keyref_t *orig = vault_keyref_new("my-key", 0, "rsa-2048", NULL, 0);
    assert_non_null(orig);
    unsigned char *bytes = NULL;
    size_t bytes_len = 0;
    assert_int_equal(0, vault_keyref_serialize(orig, &bytes, &bytes_len));
    vault_keyref_free(orig);

    wrap_malloc_fail_after(0);   /* first malloc: key_name buffer */
    vault_keyref_t *ref = vault_keyref_deserialize(bytes, bytes_len);
    assert_null(ref);

    free(bytes);
}

static void test_oom_keyref_deserialize_key_type(void **state)
{
    (void)state;
    vault_keyref_t *orig = vault_keyref_new("my-key", 0, "rsa-2048", NULL, 0);
    assert_non_null(orig);
    unsigned char *bytes = NULL;
    size_t bytes_len = 0;
    assert_int_equal(0, vault_keyref_serialize(orig, &bytes, &bytes_len));
    vault_keyref_free(orig);

    /* 1st malloc (key_name) succeeds, 2nd malloc (key_type) fails. */
    wrap_malloc_fail_after(1);
    vault_keyref_t *ref = vault_keyref_deserialize(bytes, bytes_len);
    assert_null(ref);

    free(bytes);
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_new_basic),
        cmocka_unit_test(test_new_with_version),
        cmocka_unit_test(test_new_null_name_fails),
        cmocka_unit_test(test_new_null_type_fails),
        cmocka_unit_test(test_free_null_is_safe),

        cmocka_unit_test(test_roundtrip_with_pubkey),
        cmocka_unit_test(test_roundtrip_no_pubkey),
        cmocka_unit_test(test_roundtrip_version_preserved),

        cmocka_unit_test(test_deserialize_null),
        cmocka_unit_test(test_deserialize_empty),
        cmocka_unit_test(test_deserialize_truncated),

        cmocka_unit_test(test_serialize_null),

        cmocka_unit_test(test_oom_keyref_new),
        cmocka_unit_test(test_oom_keyref_serialize),
        cmocka_unit_test(test_oom_keyref_deserialize_key_name),
        cmocka_unit_test(test_oom_keyref_deserialize_key_type),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
