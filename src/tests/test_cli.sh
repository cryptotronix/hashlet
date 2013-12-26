#!/bin/bash

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
