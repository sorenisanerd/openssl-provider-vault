AC_PREREQ([2.69])
AC_INIT([openssl-provider-vault], [0.1.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_PROG_CC
AM_PROG_AR
LT_INIT([disable-static])
AC_PROG_INSTALL

PKG_CHECK_MODULES([OPENSSL], [openssl >= 3.0.0])
PKG_CHECK_MODULES([CURL],   [libcurl])
PKG_CHECK_MODULES([JSONC],  [json-c])

AC_ARG_ENABLE([tests],
    [AS_HELP_STRING([--enable-tests], [Build test suite (requires cmocka) [default=yes]])],
    [enable_tests=$enableval], [enable_tests=yes])

AS_IF([test "x$enable_tests" = "xyes"], [
    PKG_CHECK_MODULES([CMOCKA], [cmocka],
        [have_cmocka=yes],
        [have_cmocka=no
         AC_MSG_WARN([cmocka not found; tests will not be built])])
])

AM_CONDITIONAL([ENABLE_TESTS],
    [test "x$enable_tests" = "xyes" && test "x$have_cmocka" = "xyes"])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    tests/Makefile
])
AC_OUTPUT

AC_MSG_RESULT([
    openssl-provider-vault $VERSION
    ─────────────────────────────────
    OpenSSL:   $OPENSSL_CFLAGS
    libcurl:   $CURL_CFLAGS
    json-c:    $JSONC_CFLAGS
    Tests:     $enable_tests (cmocka: ${have_cmocka:-no})
])
