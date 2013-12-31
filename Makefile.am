# Copyright (C) 2013 Cryptotronix, LLC.

# This file is part of Hashlet.

# Hashlet is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# Hashlet is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Hashlet.  If not, see <http://www.gnu.org/licenses/>.

AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = $(DEPS_CFLAGS)
hashlet_LDADD = $(DEPS_LIBS)

SUBDIRS = doc .

AM_YFLAGS = -d

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
		  src/cli/cli_commands.h src/cli/cli_commands.c \
		  src/driver/config_zone.h src/driver/config_zone.c \
		  src/parser/hashlet_bison.y src/parser/hashlet_flex.l \
		  src/parser/hashlet_parser.h src/parser/hashlet_parser.c

BUILT_SOURCES = src/parser/hashlet_bison.h

hashlet_CFLAGS = -Wall


dist_noinst_SCRIPTS = autogen.sh

TESTS = src/tests/test_cli.sh
EXTRA_DIST = src/tests/test_cli.sh
