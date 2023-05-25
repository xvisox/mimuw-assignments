#!/bin/bash

if [ $# -ne 3 ]; then
  echo "Usage: $0 <filename> <multicast_address> <name>"
  exit 1
fi

sox -S "music/$1" -r 44100 -b 16 -e signed-integer -c 2 -t raw - | pv -q -L $((44100 * 4)) |
  ./sikradio-sender -a $2 -n $3
