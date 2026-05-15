#ifndef VAULT_STORE_URI_H
#define VAULT_STORE_URI_H

/*
 * Vault STORE URI format:
 *   vault:<key-name>
 *   vault:<key-name>?version=<N>
 *
 * The scheme is "vault:" (not "vault://") — consistent with the PKCS#11
 * URI scheme which also has no authority component.
 *
 * Examples:
 *   vault:my-signing-key
 *   vault:tenant-rsa-key?version=3
 */

typedef struct {
    char *key_name;   /* heap-allocated; caller must free via vault_uri_free */
    int   version;    /* 0 = latest */
} vault_uri_t;

/*
 * Parse a vault URI into *out.
 * Returns 0 on success, -1 if the URI is not a valid vault URI.
 * On success, fields inside *out are heap-allocated; free with vault_uri_free().
 */
int vault_uri_parse(const char *uri, vault_uri_t *out);

void vault_uri_free(vault_uri_t *uri);

/*
 * Format a vault URI from components.
 * Returns a heap-allocated string; caller must free().
 * version == 0 omits the query string.
 */
char *vault_uri_format(const char *key_name, int version);

#endif /* VAULT_STORE_URI_H */
