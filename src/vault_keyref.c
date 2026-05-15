#include "vault_keyref.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Big-endian uint32 helpers. */
static void write_u32(unsigned char *p, uint32_t v)
{
    p[0] = (v >> 24) & 0xff;
    p[1] = (v >> 16) & 0xff;
    p[2] = (v >>  8) & 0xff;
    p[3] = (v      ) & 0xff;
}

static uint32_t read_u32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8)
         |  (uint32_t)p[3];
}

vault_keyref_t *vault_keyref_new(const char          *key_name,
                                  int                  key_version,
                                  const char          *key_type,
                                  const unsigned char *pubkey_der,
                                  size_t               pubkey_der_len)
{
    if (!key_name || !key_type)
        return NULL;

    vault_keyref_t *ref = calloc(1, sizeof(*ref));
    if (!ref)
        return NULL;

    ref->key_name    = strdup(key_name);
    ref->key_version = key_version;
    ref->key_type    = strdup(key_type);

    if (!ref->key_name || !ref->key_type)
        goto err;

    if (pubkey_der && pubkey_der_len > 0) {
        ref->pubkey_der = malloc(pubkey_der_len);
        if (!ref->pubkey_der)
            goto err;
        memcpy(ref->pubkey_der, pubkey_der, pubkey_der_len);
        ref->pubkey_der_len = pubkey_der_len;
    }

    return ref;

err:
    vault_keyref_free(ref);
    return NULL;
}

void vault_keyref_free(vault_keyref_t *ref)
{
    if (!ref)
        return;
    free(ref->key_name);
    free(ref->key_type);
    free(ref->pubkey_der);
    free(ref);
}

int vault_keyref_serialize(const vault_keyref_t  *ref,
                            unsigned char        **out,
                            size_t                *out_len)
{
    if (!ref || !out || !out_len)
        return -1;

    size_t name_len    = strlen(ref->key_name);
    size_t type_len    = strlen(ref->key_type);
    size_t der_len     = ref->pubkey_der_len;

    /* Each field: 4-byte length prefix + payload. */
    size_t total = 4 + name_len
                 + 4                  /* version */
                 + 4 + type_len
                 + 4 + der_len;

    unsigned char *buf = malloc(total);
    if (!buf)
        return -1;

    unsigned char *p = buf;

    write_u32(p, (uint32_t)name_len);  p += 4;
    memcpy(p, ref->key_name, name_len); p += name_len;

    write_u32(p, (uint32_t)ref->key_version); p += 4;

    write_u32(p, (uint32_t)type_len);  p += 4;
    memcpy(p, ref->key_type, type_len); p += type_len;

    write_u32(p, (uint32_t)der_len);   p += 4;
    if (der_len > 0) {
        memcpy(p, ref->pubkey_der, der_len);
        p += der_len;
    }

    (void)p; /* suppress unused-variable warning */
    *out     = buf;
    *out_len = total;
    return 0;
}

vault_keyref_t *vault_keyref_deserialize(const unsigned char *data,
                                          size_t               len)
{
    if (!data || len < 4)
        return NULL;

    const unsigned char *p   = data;
    const unsigned char *end = data + len;

#define NEED(n) do { if ((size_t)(end - p) < (n)) goto err; } while (0)

    /* name */
    NEED(4);
    uint32_t name_len = read_u32(p); p += 4;
    NEED(name_len);
    char *key_name = malloc(name_len + 1);
    if (!key_name) return NULL;
    memcpy(key_name, p, name_len);
    key_name[name_len] = '\0';
    p += name_len;

    /* version */
    NEED(4);
    int key_version = (int)read_u32(p); p += 4;

    /* key_type */
    NEED(4);
    uint32_t type_len = read_u32(p); p += 4;
    NEED(type_len);
    char *key_type = malloc(type_len + 1);
    if (!key_type) { free(key_name); return NULL; }
    memcpy(key_type, p, type_len);
    key_type[type_len] = '\0';
    p += type_len;

    /* pubkey_der */
    NEED(4);
    uint32_t der_len = read_u32(p); p += 4;
    NEED(der_len);
    unsigned char *pubkey_der = NULL;
    if (der_len > 0) {
        pubkey_der = malloc(der_len);
        if (!pubkey_der) { free(key_name); free(key_type); return NULL; }
        memcpy(pubkey_der, p, der_len);
    }

#undef NEED

    vault_keyref_t *ref = vault_keyref_new(key_name, key_version,
                                            key_type,
                                            pubkey_der, (size_t)der_len);
    free(key_name);
    free(key_type);
    free(pubkey_der);
    return ref;

err:
    return NULL;
}
