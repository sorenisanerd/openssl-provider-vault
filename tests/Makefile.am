if ENABLE_TESTS

# Each test binary links the source files it exercises directly, plus the
# mock Vault client (instead of the real libcurl-backed one).  This keeps
# each test self-contained and avoids loading the full provider shared lib.

COMMON_CFLAGS = $(OPENSSL_CFLAGS) $(CMOCKA_CFLAGS) -I$(top_srcdir)/src
COMMON_LDADD  = $(OPENSSL_LIBS)   $(CMOCKA_LIBS)

check_PROGRAMS = \
    test_format       \
    test_keyref       \
    test_store_uri    \
    test_keymgmt      \
    test_signature    \
    test_store        \
    test_vault_client

TESTS = $(check_PROGRAMS)

# ── test_format ─────────────────────────────────────────────────────────────
test_format_SOURCES = test_format.c \
    $(top_srcdir)/src/vault_format.c
test_format_CFLAGS  = $(COMMON_CFLAGS)
test_format_LDADD   = $(COMMON_LDADD)

# ── test_keyref ─────────────────────────────────────────────────────────────
test_keyref_SOURCES = test_keyref.c \
    $(top_srcdir)/src/vault_keyref.c \
    $(top_srcdir)/src/vault_format.c
test_keyref_CFLAGS  = $(COMMON_CFLAGS)
test_keyref_LDADD   = $(COMMON_LDADD)

# ── test_store_uri ───────────────────────────────────────────────────────────
test_store_uri_SOURCES = test_store_uri.c \
    $(top_srcdir)/src/vault_store_uri.c
test_store_uri_CFLAGS  = $(COMMON_CFLAGS)
test_store_uri_LDADD   = $(COMMON_LDADD)

# ── test_keymgmt ─────────────────────────────────────────────────────────────
# Links mock_vault_client.c instead of vault_client.c
test_keymgmt_SOURCES = test_keymgmt.c mock_vault_client.c \
    $(top_srcdir)/src/keymgmt.c       \
    $(top_srcdir)/src/vault_keyref.c  \
    $(top_srcdir)/src/vault_format.c
test_keymgmt_CFLAGS  = $(COMMON_CFLAGS)
test_keymgmt_LDADD   = $(COMMON_LDADD)

# ── test_signature ────────────────────────────────────────────────────────────
test_signature_SOURCES = test_signature.c mock_vault_client.c \
    $(top_srcdir)/src/signature.c     \
    $(top_srcdir)/src/vault_keyref.c  \
    $(top_srcdir)/src/vault_format.c
test_signature_CFLAGS  = $(COMMON_CFLAGS)
test_signature_LDADD   = $(COMMON_LDADD)

# ── test_store ────────────────────────────────────────────────────────────
test_store_SOURCES = test_store.c mock_vault_client.c \
    $(top_srcdir)/src/store.c           \
    $(top_srcdir)/src/vault_store_uri.c \
    $(top_srcdir)/src/vault_keyref.c    \
    $(top_srcdir)/src/vault_format.c
test_store_CFLAGS  = $(COMMON_CFLAGS)
test_store_LDADD   = $(COMMON_LDADD)

# ── test_vault_client (integration — skipped unless VAULT_ADDR/TOKEN set) ──
test_vault_client_SOURCES = test_vault_client.c \
    $(top_srcdir)/src/vault_client.c  \
    $(top_srcdir)/src/vault_format.c  \
    $(top_srcdir)/src/vault_keyref.c
test_vault_client_CFLAGS  = $(COMMON_CFLAGS) $(CURL_CFLAGS) $(JSONC_CFLAGS)
test_vault_client_LDADD   = $(COMMON_LDADD) $(CURL_LIBS) $(JSONC_LIBS)

endif
