#!/bin/sh

set -eux

curl -fsSL https://github.com/wlallemand/VTest/archive/refs/heads/haproxy-sd_notify.tar.gz -o VTest.tar.gz
mkdir ../vtest
tar xvf VTest.tar.gz -C ../vtest --strip-components=1
# Special flags due to: https://github.com/vtest/VTest/issues/12

# Note: do not use "make -C ../vtest", otherwise MAKEFLAGS contains "w"
# and fails (see Options/Recursion in GNU Make doc, it contains the list
# of options without the leading '-').
# MFLAGS works on BSD but misses variable definitions on GNU Make.
# Better just avoid the -C and do the cd ourselves then.

cd ../vtest

set +e
CPUS=${CPUS:-$(nproc 2>/dev/null)}
CPUS=${CPUS:-1}
set -e

#
# temporarily detect Apple Silicon (it's using /opt/homebrew instead of /usr/local)
#
if test -f /opt/homebrew/include/pcre2.h; then
   make -j${CPUS} FLAGS="-O2 -s -Wall" INCS="-Isrc -Ilib -I/usr/local/include -I/opt/homebrew/include -pthread"
else
   make -j${CPUS} FLAGS="-O2 -s -Wall"
fi
