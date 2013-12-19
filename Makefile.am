AUTOMAKE_OPTIONS = subdir-objects
SUBDIRS = .
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CPPFLAGS = $(DEPS_CFLAGS)
hashlet_LDADD = $(DEPS_LIBS)

bin_PROGRAMS = hashlet
hashlet_SOURCES = src/command.h src/command.c src/crc.h src/crc.c \
		  src/defs.h src/i2c.h src/i2c.c src/test.c src/util.h \
		  src/util.c src/command_adaptation.h src/command_adaptation.c \
	          src/log.h src/log.c

#hashlet_CPPFLAGS = $(DEPS_CFLAGS)
#hashlet_LDFLAGS = $(DEPS_LDFLAGS)

dist_noinst_SCRIPTS = autogen.sh
