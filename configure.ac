AC_INIT([hashlet], [0.1], [bugs@cryptotronix.com], [hashlet], [http://www.github.com/cryptotronix/hashlet/])
AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 -Wall no-define])
AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADERS([linux/i2c-dev.h sys/ioctl.h fcntl.h])
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_FILES([Makefile])
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([DEPS], [gnutls >= 2.12.20])
AC_OUTPUT
