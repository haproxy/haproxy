#!/bin/sh

set -eux

curl -fsSL https://github.com/vtest/VTest/archive/master.tar.gz -o VTest.tar.gz
mkdir ../vtest
tar xvf VTest.tar.gz -C ../vtest --strip-components=1
# Special flags due to: https://github.com/vtest/VTest/issues/12

#
# temporarily detect Apple Silicon (it's using /opt/homebrew instead of /usr/local)
#
if test -f /opt/homebrew/include/pcre2.h; then
   make -C ../vtest FLAGS="-O2 -s -Wall" INCS="-Isrc -Ilib -I/usr/local/include -I/opt/homebrew/include -pthread"
else
   make -C ../vtest FLAGS="-O2 -s -Wall"
fi
