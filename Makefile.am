AUTOMAKE_OPTIONS = subdir-objects
SUBDIRS = .
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CPPFLAGS = $(DEPS_CFLAGS)
hashlet_LDADD = $(DEPS_LIBS)

bin_PROGRAMS = hashlet
hashlet_SOURCES = src/driver/command.h src/driver/command.c \
	          src/driver/crc.h src/driver/crc.c \
	          src/driver/defs.h \
	          src/driver/i2c.h src/driver/i2c.c \
	          src/driver/util.h src/driver/util.c \
	          src/driver/command_adaptation.h src/driver/command_adaptation.c \
	          src/driver/log.h src/driver/log.c \
	          src/cli/main.c \
	          src/driver/hashlet.h \
		  src/driver/personalize.h src/driver/personalize.c \
		  src/cli/hash.h src/cli/hash.c \
		  src/cli/cli_commands.h src/cli/cli_commands.c

hashlet_CFLAGS = -Wall -Werror


dist_noinst_SCRIPTS = autogen.sh

TESTS = src/tests/test_cli.sh
