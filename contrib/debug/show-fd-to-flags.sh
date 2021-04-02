#!/bin/sh
awk '{print $12}' | grep cflg= | sort | uniq -c | sort -nr | while read a b; do c=${b##*=}; d=$(${0%/*}/flags conn $c);d=${d##*= }; printf "%6d %s    %s\n" $a "$b" "$d";done
