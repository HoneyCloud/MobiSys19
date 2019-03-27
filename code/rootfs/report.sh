#! /bin/sh

while true
do
  grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {printf("\x10%d\n", usage)}' | nc -u -p1234 10.0.2.2 5000; sleep 1; killall nc
  ps | echo -n -e "\x11$(cat -)" | nc -u -p1234 10.0.2.2 5000; sleep 1; killall nc
  sleep 60
done