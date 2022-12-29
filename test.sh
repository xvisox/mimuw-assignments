#!/bin/bash

PROG=${1}

for f in ./programs/*.cpp
do
    echo $f
    name=$(basename -- $f)
    g++ $f -o ${name%.cpp}
done

for t in ./tests/*.in
do
    name=$(basename -- $t)
    echo $name
    ./$PROG <$t #>${name%.in}.out
done
