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

test_exit(){
    if [[ $? == $1 ]]; then
        echo $2 passed
    else
        echo $2 failed
        exit 1
    fi
}


SUCCESS=0
FAIL=1

BUS=/dev/i2c-1
EXE=./hashlet

BUS=/dev/i2c-1

if [[ ! -e $BUS ]]; then
    BUS=/dev/i2c-2
fi

echo "Testing I2C"
for i in {0..20..1}
do
    STATE=$($EXE state -b $BUS)
    if [[ $STATE != "Factory" ]]; then
        echo State check failed
        exit 1
    fi
done

echo "I2C Test passed"

#Verify it's factory random data
RSP=$($EXE random -b $BUS)

FAC_RANDOM=FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000

if [[ $RSP != $FAC_RANDOM ]]; then
    echo Random check failed
    exit 1
fi

echo "Random test passed"

SERIAL=$($EXE serial-num -b $BUS)

echo $SERIAL | sed 's/.\{2\}/& /g'
echo "Ready to ship!"
