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

if [[ ! -e $BUS ]]; then
    BUS=/dev/i2c-2
fi

STATE=$($EXE state -b $BUS)

#These tests are for a personalized hashlet

if [[ $STATE == "Personalized" ]] || [[ $STATE == "Initialized" ]] || \
   [[ $STATE == "Factory" ]]; then
    echo State check passed
else
    echo State check failed
    exit 1
fi

RSP=$($EXE random -b $BUS)

if [ "${#RSP}" == 64 ]; then
    echo Random length passed
else
    echo Random length failed
    exit 1
fi

RSP=$($EXE random -b /dev/i2c-4)
test_exit 1 "Wrong Bus"

RSP=$($EXE mac -f config.log -b $BUS)
test_exit 0 "Mac command"

echo $RSP

mac=$(echo $RSP| awk '{print $3}')
chal=$(echo $RSP| awk '{print $6}')
meta=$(echo $RSP| awk '{print $9}')

RSP=$($EXE check-mac -r $mac -c $chal -m $meta -b $BUS)

test_exit $SUCCESS check-mac


# Negative testing on MAC command
RSP=$($EXE check-mac -r $mac -c $chal -b $BUS)

test_exit $FAIL check-mac
RSP=$($EXE check-mac -r $mac  -m $meta -b $BUS)
test_exit $FAIL check-mac
RSP=$($EXE check-mac -m $meta -c $chal -b $BUS)
test_exit $FAIL check-mac

RSP=$($EXE serial-num -b $BUS)
test_exit $SUCCESS serial-num

if [ "${#RSP}" == 18 ]; then
    echo Serial length passed
else
    echo Serial length failed
    exit 1
fi

#test offline feature
RSP=$($EXE offline-verify -r $mac -c $chal -b $BUS)

test_exit $SUCCESS offline-verify
