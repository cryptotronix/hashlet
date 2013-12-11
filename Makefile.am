AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CPPFLAGS = $(HASHLET_CFLAGS)
hashlet_LDADD = $(HASHLET_LIBS)

bin_PROGRAMS = hashlet
hashlet_SOURCES = src/command.h src/command.c src/crc.h src/crc.c \
		  src/defs.h src/i2c.h src/i2c.c src/test.c src/util.h \
		  src/util.c src/command_adaptation.h src/command_adaptation.c


dist_noinst_SCRIPTS = autogen.sh
