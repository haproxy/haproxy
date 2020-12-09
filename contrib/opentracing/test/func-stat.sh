#!/bin/sh
#
test ${#} -lt 1 && exit 1

awk '/ {$/ { sub(/\(.*/, "", $5); print $5 }' "${@}" | sort | uniq -c
