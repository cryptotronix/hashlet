#!/bin/bash
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


BUS=/dev/i2c-1
EXE=./hashlet

STATE=$($EXE $BUS state)

if [[ $STATE == "Personalized" ]] || [[ $STATE == "Initialized" ]] || \
   [[$STATE == "Factory"]]; then
    echo State check passed
else
    echo State check failed
    exit 1
fi

RSP=$($EXE $BUS random)

if [ "${#RSP}" == 64 ]; then
    echo Random length passed
else
    echo Random length failed
    exit 1
fi
