#!/bin/sh

set -eux

curl -fsSL https://github.com/vtest/VTest/archive/master.tar.gz -o VTest.tar.gz
mkdir ../vtest
tar xvf VTest.tar.gz -C ../vtest --strip-components=1
# Special flags due to: https://github.com/vtest/VTest/issues/12
make -C ../vtest FLAGS="-O2 -s -Wall"

