#!/bin/sh
PORT=53
if [ "${1}" = "-4" -o "${1}" = "-6" ]
then
  vers=${1}
  shift
else
  vers="-6"
fi
host=${1-0}
args=""
if [ $# -gt 2 ]
then
  shift; 
  args="$@"
fi
echo "Setting up DNS AXFR query for '$args' @ $host"
exec tcpclient -v -RHl0 "$vers" "$host" "$PORT" axfr-get $args
