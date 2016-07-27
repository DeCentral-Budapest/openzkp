AC_PREREQ([2.69])
AC_INIT([OpenZKP], [0.0.1], [])
AM_INIT_AUTOMAKE()
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
LT_INIT
AC_CHECK_HEADERS([openssl/bn.h openssl/rand.h])
AC_CHECK_LIB([crypto], [BN_new])
AC_CHECK_LIB([crypto], [RAND_bytes])
AC_CHECK_LIB([m], [pow])
AC_FUNC_MALLOC
AC_PREFIX_DEFAULT(/usr)
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
