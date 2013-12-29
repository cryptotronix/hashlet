#!/bin/bash

result=""

while [[ ${#result} -lt 5000 ]]; do
    random=$(./hashlet /dev/i2c-1 random)
    result=$result$random
done

echo $result
