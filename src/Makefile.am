pkglibdir = $(libdir)/ossl-modules

pkglib_LTLIBRARIES = vault.la

vault_la_SOURCES = \
    provider.c    \
    provider.h    \
    vault_client.c \
    vault_client.h \
    vault_format.c \
    vault_format.h \
    vault_keyref.c \
    vault_keyref.h \
    vault_store_uri.c \
    vault_store_uri.h \
    keymgmt.c      \
    keymgmt.h      \
    signature.c    \
    signature.h    \
    asym_cipher.c  \
    asym_cipher.h  \
    mac.c          \
    mac.h          \
    store.c

vault_la_CFLAGS  = $(OPENSSL_CFLAGS) $(CURL_CFLAGS) $(JSONC_CFLAGS) -fvisibility=hidden
vault_la_LIBADD  = $(OPENSSL_LIBS) $(CURL_LIBS) $(JSONC_LIBS)
vault_la_LDFLAGS = -module -avoid-version -shared \
                   -export-symbols-regex '^OSSL_provider_init$$'
