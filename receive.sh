#!/bin/bash

if [ $# -ne 1 ]; then
  echo "Usage: $0 <name>"
  exit 1
fi

./sikradio-receiver -n $1 |
  play -t raw -c 2 -r 44100 -b 16 -e signed-integer --buffer 8192 -
