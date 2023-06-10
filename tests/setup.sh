#!/usr/bin/env bash

make test-exclusive-lock
make test-exclusive-unlock
make test-fexclusive
make test-permissions
make test-open
make test-open-and-read
touch nowy.c
touch pliczek.c
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
