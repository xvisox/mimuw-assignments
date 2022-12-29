#!/bin/bash

PROG=${1}

# shellcheck disable=SC2164
cd build
make
# shellcheck disable=SC2103
cd ..

for f in ./programs/*.cc; do
  echo $f
  name=$(basename -- $f)
  g++ $f -o ${name%.cc}
done
#
#for t in ./tests/*.in; do
#  name=$(basename -- $t)
#  echo $name
#  ./$PROG <$t #>${name%.in}.out
#done
