#include "vault_client.h"
#include "vault_format.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

/* ── context ─────────────────────────────────────────────────────────── */

struct vault_ctx {
    char *addr;     /* e.g. "https://vault.example.com:8200" — no trailing slash */
    char *token;
    char *ns;       /* Vault namespace; NULL if not used */
};

vault_ctx_t *vault_ctx_new(const char *addr, const char *token, const char *ns)
{
    if (!addr || !token) return NULL;

    vault_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->addr  = strdup(addr);
    ctx->token = strdup(token);
    ctx->ns    = ns ? strdup(ns) : NULL;

    if (!ctx->addr || !ctx->token) {
        vault_ctx_free(ctx);
        return NULL;
    }
    return ctx;
}

void vault_ctx_free(vault_ctx_t *ctx)
{
    if (!ctx) return;
    free(ctx->addr);
    free(ctx->token);
    free(ctx->ns);
    free(ctx);
}

/* ── libcurl response accumulator ────────────────────────────────────── */

typedef struct {
    char  *data;
    size_t size;
} resp_buf_t;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
    size_t total = size * nmemb;
    resp_buf_t *buf = (resp_buf_t *)userp;

    char *tmp = realloc(buf->data, buf->size + total + 1);
    if (!tmp) return 0;
    buf->data = tmp;
    memcpy(buf->data + buf->size, ptr, total);
    buf->size += total;
    buf->data[buf->size] = '\0';
    return total;
}

/* ── HTTP helper ─────────────────────────────────────────────────────── */

/*
 * POST (body != NULL) or GET (body == NULL) to <addr>/v1/transit/<path>.
 * Returns the HTTP status code, or -1 on libcurl error.
 * *response_out is set to the malloc'd response body (caller must free).
 */
static int vault_http(vault_ctx_t *ctx, const char *path,
                       const char *body, char **response_out)
{
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[2048];
    snprintf(url, sizeof(url), "%s/v1/transit/%s", ctx->addr, path);

    char auth_hdr[512];
    snprintf(auth_hdr, sizeof(auth_hdr), "X-Vault-Token: %s", ctx->token);

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, auth_hdr);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    if (ctx->ns) {
        char ns_hdr[256];
        snprintf(ns_hdr, sizeof(ns_hdr), "X-Vault-Namespace: %s", ctx->ns);
        hdrs = curl_slist_append(hdrs, ns_hdr);
    }

    resp_buf_t resp = {0};

    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &resp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       30L);

    if (body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    }

    CURLcode res  = curl_easy_perform(curl);
    long http_code = 0;
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(resp.data);
        return -1;
    }

    *response_out = resp.data ? resp.data : strdup("");
    return (int)http_code;
}

static int http_ok(int code) { return code >= 200 && code < 300; }

/* ── json-c helpers ──────────────────────────────────────────────────── */

/*
 * Parse JSON and walk a dot-separated path (e.g. "data.signature").
 * Returns a borrowed json_object reference (owned by root); do not free.
 */
static json_object *jpath(json_object *root, const char *path)
{
    char buf[256];
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    json_object *cur = root;
    char *tok = strtok(buf, ".");
    while (tok && cur) {
        if (!json_object_is_type(cur, json_type_object))
            return NULL;
        json_object *child = NULL;
        json_object_object_get_ex(cur, tok, &child);
        cur = child;
        tok = strtok(NULL, ".");
    }
    return cur;
}

static const char *jstr(json_object *root, const char *path)
{
    json_object *obj = jpath(root, path);
    if (!obj || !json_object_is_type(obj, json_type_string))
        return NULL;
    return json_object_get_string(obj);
}

static int jbool(json_object *root, const char *path, int *out)
{
    json_object *obj = jpath(root, path);
    if (!obj) return -1;
    if (!json_object_is_type(obj, json_type_boolean))
        return -1;
    *out = json_object_get_boolean(obj) ? 1 : 0;
    return 0;
}

static int jint(json_object *root, const char *path, int *out)
{
    json_object *obj = jpath(root, path);
    if (!obj) return -1;
    if (!json_object_is_type(obj, json_type_int))
        return -1;
    *out = json_object_get_int(obj);
    return 0;
}

/* ── PEM → DER conversion ────────────────────────────────────────────── */

static int pem_pubkey_to_der(const char *pem,
                               unsigned char **der_out, size_t *der_len_out)
{
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return -1;

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) return -1;

    int len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0) { EVP_PKEY_free(pkey); return -1; }

    unsigned char *buf = malloc((size_t)len);
    if (!buf) { EVP_PKEY_free(pkey); return -1; }

    unsigned char *p = buf;
    len = i2d_PUBKEY(pkey, &p);
    EVP_PKEY_free(pkey);

    if (len <= 0) { free(buf); return -1; }

    *der_out     = buf;
    *der_len_out = (size_t)len;
    return 0;
}

/* ── vault_get_key ───────────────────────────────────────────────────── */

int vault_get_key(vault_ctx_t *ctx, const char *key_name,
                  vault_key_info_t *info_out)
{
    char path[512];
    snprintf(path, sizeof(path), "keys/%s", key_name);

    char *body     = NULL;   /* GET — no body */
    char *response = NULL;
    int code = vault_http(ctx, path, body, &response);
    if (!http_ok(code)) { free(response); return -1; }

    json_object *root = json_tokener_parse(response);
    free(response);
    if (!root) return -1;

    int rc = -1;

    const char *type = jstr(root, "data.type");
    if (!type) goto out;

    int latest = 0;
    if (jint(root, "data.latest_version", &latest) != 0) goto out;

    int min_decrypt = 0;
    jint(root, "data.min_decryption_version", &min_decrypt);

    memset(info_out, 0, sizeof(*info_out));
    info_out->key_type             = strdup(type);
    info_out->latest_version       = latest;
    info_out->min_decrypt_version  = min_decrypt;

    /* Extract the public key for the latest version, if present.
     * Response shape: data.keys."<N>".public_key  (PEM string) */
    json_object *keys_obj = jpath(root, "data.keys");
    if (keys_obj && json_object_is_type(keys_obj, json_type_object)) {
        char ver_str[32];
        snprintf(ver_str, sizeof(ver_str), "%d", latest);

        json_object *ver_obj = NULL;
        json_object_object_get_ex(keys_obj, ver_str, &ver_obj);
        if (ver_obj) {
            json_object *pk_obj = NULL;
            json_object_object_get_ex(ver_obj, "public_key", &pk_obj);
            if (pk_obj && json_object_is_type(pk_obj, json_type_string)) {
                const char *pem = json_object_get_string(pk_obj);
                pem_pubkey_to_der(pem,
                                   &info_out->pubkey_der,
                                   &info_out->pubkey_der_len);
                /* Not fatal if we can't parse the public key (e.g. HMAC key). */
            }
        }
    }

    rc = 0;

out:
    json_object_put(root);
    if (rc != 0) {
        free(info_out->key_type);
        memset(info_out, 0, sizeof(*info_out));
    }
    return rc;
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
    char path[512];
    snprintf(path, sizeof(path), "keys/%s", key_name);

    char *body = NULL;
    /* HMAC keys require key_size (32–512 bytes); use 32 as the default. */
    if (strcmp(key_type, "hmac") == 0) {
        if (asprintf(&body,
                     "{\"type\":\"%s\",\"exportable\":%s,\"key_size\":32}",
                     key_type,
                     exportable ? "true" : "false") < 0)
            return -1;
    } else {
        if (asprintf(&body,
                     "{\"type\":\"%s\",\"exportable\":%s}",
                     key_type,
                     exportable ? "true" : "false") < 0)
            return -1;
    }

    char *response = NULL;
    int code = vault_http(ctx, path, body, &response);
    free(body);
    free(response);
    return http_ok(code) ? 0 : -1;
}

/* ── vault_sign ──────────────────────────────────────────────────────── */

int vault_sign(vault_ctx_t *ctx,
               const char *key_name, int key_version,
               const char *hash_alg, const char *sig_alg,
               const unsigned char *input, size_t input_len,
               unsigned char **sig_out, size_t *sig_out_len)
{
    char *input_b64 = vault_request_encode(input, input_len);
    if (!input_b64) return -1;

    char path[512];
    snprintf(path, sizeof(path), "sign/%s", key_name);

    char *body = NULL;
    if (asprintf(&body,
                 "{"
                 "\"input\":\"%s\","
                 "\"hash_algorithm\":\"%s\","
                 "\"signature_algorithm\":\"%s\","
                 "\"prehashed\":true,"
                 "\"key_version\":%d"
                 "}",
                 input_b64, hash_alg, sig_alg, key_version) < 0) {
        free(input_b64);
        return -1;
    }
    free(input_b64);

    char *response = NULL;
    int code = vault_http(ctx, path, body, &response);
    free(body);
    if (!http_ok(code)) { free(response); return -1; }

    json_object *root = json_tokener_parse(response);
    free(response);
    if (!root) return -1;

    int rc = -1;
    const char *vault_sig = jstr(root, "data.signature");
    if (vault_sig)
        rc = vault_response_decode(vault_sig, sig_out, sig_out_len);

    json_object_put(root);
    return rc;
}

/* ── vault_verify ────────────────────────────────────────────────────── */

int vault_verify(vault_ctx_t *ctx,
                 const char *key_name, int key_version,
                 const char *hash_alg, const char *sig_alg,
                 const unsigned char *input, size_t input_len,
                 const unsigned char *sig, size_t sig_len,
                 int *valid_out)
{
    char *input_b64   = vault_request_encode(input, input_len);
    char *vault_sig   = vault_response_encode(sig, sig_len);
    if (!input_b64 || !vault_sig) {
        free(input_b64);
        free(vault_sig);
        return -1;
    }

    char path[512];
    snprintf(path, sizeof(path), "verify/%s", key_name);

    char *body = NULL;
    if (asprintf(&body,
                 "{"
                 "\"input\":\"%s\","
                 "\"signature\":\"%s\","
                 "\"hash_algorithm\":\"%s\","
                 "\"signature_algorithm\":\"%s\","
                 "\"prehashed\":true,"
                 "\"key_version\":%d"
                 "}",
                 input_b64, vault_sig, hash_alg, sig_alg, key_version) < 0) {
        free(input_b64);
        free(vault_sig);
        return -1;
    }
    free(input_b64);
    free(vault_sig);

    char *response = NULL;
    int code = vault_http(ctx, path, body, &response);
    free(body);
    if (!http_ok(code)) { free(response); return -1; }

    json_object *root = json_tokener_parse(response);
    free(response);
    if (!root) return -1;

    int rc = jbool(root, "data.valid", valid_out);
    json_object_put(root);
    return rc;
}

/* ── encrypt / decrypt (shared path for asym and sym) ───────────────── */

/*
 * Vault uses the same endpoints for RSA and symmetric encryption.
 * The "ciphertext" returned is the full "vault:v1:..." string — we store
 * it as the opaque ciphertext bytes so we can round-trip it to decrypt.
 */
static int vault_encrypt_inner(vault_ctx_t *ctx,
                                const char *key_name, int key_version,
                                const unsigned char *plaintext, size_t plaintext_len,
                                unsigned char **ct_out, size_t *ct_out_len)
{
    char *pt_b64 = vault_request_encode(plaintext, plaintext_len);
    if (!pt_b64) return -1;

    char path[512];
    snprintf(path, sizeof(path), "encrypt/%s", key_name);

    char *body = NULL;
    if (asprintf(&body,
                 "{\"plaintext\":\"%s\",\"key_version\":%d}",
                 pt_b64, key_version) < 0) {
        free(pt_b64);
        return -1;
    }
    free(pt_b64);

    char *response = NULL;
    int code = vault_http(ctx, path, body, &response);
    free(body);
    if (!http_ok(code)) { free(response); return -1; }

    json_object *root = json_tokener_parse(response);
    free(response);
    if (!root) return -1;

    int rc = -1;
    const char *ct_str = jstr(root, "data.ciphertext");
    if (ct_str) {
        /* Store the full vault:vN:... string as the ciphertext bytes. */
        size_t len = strlen(ct_str);
        *ct_out = malloc(len + 1);
        if (*ct_out) {
            memcpy(*ct_out, ct_str, len + 1);
            *ct_out_len = len;
            rc = 0;
        }
    }

    json_object_put(root);
    return rc;
}

static int vault_decrypt_inner(vault_ctx_t *ctx,
                                const char *key_name, int key_version,
                                const unsigned char *ciphertext, size_t ciphertext_len,
                                unsigned char **pt_out, size_t *pt_out_len)
{
    /* ciphertext is the vault:vN:... string stored by vault_encrypt_inner. */
    char *ct_str = malloc(ciphertext_len + 1);
    if (!ct_str) return -1;
    memcpy(ct_str, ciphertext, ciphertext_len);
    ct_str[ciphertext_len] = '\0';

    char path[512];
    snprintf(path, sizeof(path), "decrypt/%s", key_name);

    char *body = NULL;
    if (asprintf(&body,
                 "{\"ciphertext\":\"%s\",\"key_version\":%d}",
                 ct_str, key_version) < 0) {
        free(ct_str);
        return -1;
    }
    free(ct_str);

    char *response = NULL;
    int code = vault_http(ctx, path, body, &response);
    free(body);
    if (!http_ok(code)) { free(response); return -1; }

    json_object *root = json_tokener_parse(response);
    free(response);
    if (!root) return -1;

    int rc = -1;
    const char *pt_b64 = jstr(root, "data.plaintext");
    if (pt_b64)
        rc = vault_base64_decode(pt_b64, pt_out, pt_out_len);

    json_object_put(root);
    return rc;
}

int vault_asym_encrypt(vault_ctx_t *ctx,
                       const char *key_name, int key_version,
                       const unsigned char *plaintext, size_t plaintext_len,
                       unsigned char **ciphertext_out, size_t *ciphertext_out_len)
{
    return vault_encrypt_inner(ctx, key_name, key_version,
                                plaintext, plaintext_len,
                                ciphertext_out, ciphertext_out_len);
}

int vault_asym_decrypt(vault_ctx_t *ctx,
                       const char *key_name, int key_version,
                       const unsigned char *ciphertext, size_t ciphertext_len,
                       unsigned char **plaintext_out, size_t *plaintext_out_len)
{
    return vault_decrypt_inner(ctx, key_name, key_version,
                                ciphertext, ciphertext_len,
                                plaintext_out, plaintext_out_len);
}

int vault_sym_encrypt(vault_ctx_t *ctx,
                      const char *key_name, int key_version,
                      const unsigned char *plaintext, size_t plaintext_len,
                      unsigned char **ciphertext_out, size_t *ciphertext_out_len)
{
    return vault_encrypt_inner(ctx, key_name, key_version,
                                plaintext, plaintext_len,
                                ciphertext_out, ciphertext_out_len);
}

int vault_sym_decrypt(vault_ctx_t *ctx,
                      const char *key_name, int key_version,
                      const unsigned char *ciphertext, size_t ciphertext_len,
                      unsigned char **plaintext_out, size_t *plaintext_out_len)
{
    return vault_decrypt_inner(ctx, key_name, key_version,
                                ciphertext, ciphertext_len,
                                plaintext_out, plaintext_out_len);
}

/* ── vault_hmac ──────────────────────────────────────────────────────── */

int vault_hmac(vault_ctx_t *ctx,
               const char *key_name, int key_version,
               const char *algorithm,
               const unsigned char *input, size_t input_len,
               unsigned char **hmac_out, size_t *hmac_out_len)
{
    char *input_b64 = vault_request_encode(input, input_len);
    if (!input_b64) return -1;

    char path[512];
    snprintf(path, sizeof(path), "hmac/%s/%s", key_name, algorithm);

    char *body = NULL;
    if (asprintf(&body,
                 "{\"input\":\"%s\",\"key_version\":%d}",
                 input_b64, key_version) < 0) {
        free(input_b64);
        return -1;
    }
    free(input_b64);

    char *response = NULL;
    int code = vault_http(ctx, path, body, &response);
    free(body);
    if (!http_ok(code)) { free(response); return -1; }

    json_object *root = json_tokener_parse(response);
    free(response);
    if (!root) return -1;

    int rc = -1;
    const char *vault_hmac_str = jstr(root, "data.hmac");
    if (vault_hmac_str)
        rc = vault_response_decode(vault_hmac_str, hmac_out, hmac_out_len);

    json_object_put(root);
    return rc;
}

/* ── vault_hash ──────────────────────────────────────────────────────── */

int vault_hash(vault_ctx_t *ctx,
               const char *algorithm,
               const unsigned char *input, size_t input_len,
               unsigned char **hash_out, size_t *hash_out_len)
{
    char *input_b64 = vault_request_encode(input, input_len);
    if (!input_b64) return -1;

    char path[128];
    snprintf(path, sizeof(path), "hash/%s", algorithm);

    char *body = NULL;
    if (asprintf(&body, "{\"input\":\"%s\"}", input_b64) < 0) {
        free(input_b64);
        return -1;
    }
    free(input_b64);

    char *response = NULL;
    int code = vault_http(ctx, path, body, &response);
    free(body);
    if (!http_ok(code)) { free(response); return -1; }

    json_object *root = json_tokener_parse(response);
    free(response);
    if (!root) return -1;

    int rc = -1;
    const char *sum_str = jstr(root, "data.sum");
    if (sum_str)
        rc = vault_response_decode(sum_str, hash_out, hash_out_len);

    json_object_put(root);
    return rc;
}

/* ── vault_random ────────────────────────────────────────────────────── */

int vault_random(vault_ctx_t *ctx, size_t bytes, unsigned char **random_out)
{
    char path[128];
    snprintf(path, sizeof(path), "random/%zu", bytes);

    char *response = NULL;
    /* POST with empty body — Vault accepts it */
    int code = vault_http(ctx, path, "{}", &response);
    if (!http_ok(code)) { free(response); return -1; }

    json_object *root = json_tokener_parse(response);
    free(response);
    if (!root) return -1;

    int rc = -1;
    const char *rb_str = jstr(root, "data.random_bytes");
    if (rb_str) {
        size_t decoded_len = 0;
        rc = vault_base64_decode(rb_str, random_out, &decoded_len);
        if (rc == 0 && decoded_len != bytes) {
            /* Vault should always return exactly the requested count. */
            free(*random_out);
            rc = -1;
        }
    }

    json_object_put(root);
    return rc;
}
