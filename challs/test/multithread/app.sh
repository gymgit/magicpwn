#!/bin/bash

rnd=$(($RANDOM % 256))
echo "$rnd"
echo "Enter your guess!"
echo "> "
read -r guess
if [[ "$guess" -eq "$rnd" ]]; then
    echo "Success here is your shell"
    echo "> "
    /bin/bash
else
    echo "Wrong!!"
    echo "> "
    read -r whatever
fi
