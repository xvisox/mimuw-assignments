#!/usr/bin/env bash

make test-exclusive-lock
make test-exclusive-unlock
make test-fexclusive
make test-permissions
touch nowy.c
chmod ugo+rwx *

user add -m -g users alice
su - alice

# cd /root/tests
#
# ./test-fexclusive hello.c
#
# exit
# cd /root/tests
#
# ./test-permissions hello.c
