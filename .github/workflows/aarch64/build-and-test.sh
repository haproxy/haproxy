#!/usr/bin/env bash

set -eox

export TARGET="linux-glibc"
export FLAGS="USE_ZLIB=1 USE_PCRE=1 USE_PCRE_JIT=1 USE_LUA=1 USE_OPENSSL=0 USE_SYSTEMD=1 USE_WURFL=1 WURFL_INC=contrib/wurfl WURFL_LIB=contrib/wurfl USE_DEVICEATLAS=1 DEVICEATLAS_SRC=contrib/deviceatlas USE_51DEGREES=1"
export SSL_LIB=${HOME}/opt/lib
export SSL_INC=${HOME}/opt/include
export TMPDIR=/tmp
export FIFTYONEDEGREES_SRC="contrib/51d/src/pattern"
export DEBUG_OPTIONS="DEBUG_STRICT=1"
export CC=clang-9

pushd /haproxy
echo "Target: $TARGET"
make clean 
make -C ./vtest FLAGS="-O2 -s -Wall"
bash ./scripts/build-ssl.sh
make -C contrib/wurfl
make -j3 ERR=1 DEBUG_STRICT=1 V=0 TARGET=$TARGET $FLAGS DEBUG_CFLAGS="$DEBUG_CFLAGS" LDFLAGS="$LDFLAGS -L$SSL_LIB -Wl,-rpath,$SSL_LIB" 51DEGREES_SRC="$FIFTYONEDEGREES_SRC" EXTRA_OBJS="$EXTRA_OBJS" LUA_INC=/usr/include/lua5.3/

./haproxy -vv
ldd haproxy

VTEST_PROGRAM=./vtest/vtest REGTESTS_TYPES=default,bug,devel,slow make reg-tests

popd