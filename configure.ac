AC_INIT([hashlet], [0.1.0], [bugs@cryptotronix.com], [hashlet], [http://www.github.com/cryptotronix/hashlet/])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 -Wall no-define])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADERS([linux/i2c-dev.h sys/ioctl.h fcntl.h gcrypt.h])
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_FILES([Makefile])
PKG_PROG_PKG_CONFIG
#Check for libs
have_gcrypt=no
AC_SEARCH_LIBS([gcry_md_open], [gcrypt], [have_gcrypt=yes])

if test "x${have_gcrypt}" = xno; then
   AC_MSG_WARN([
   ----------------------------------------------------
   Unable to find gcrypt.h on this system.
   Some features are disabled, install libgcrypt and
   rebuild to enable them.
   ----------------------------------------------------])
fi

AM_PROG_LEX
AC_PROG_YACC
AC_PROG_LIBTOOL


AC_OUTPUT
