#!/usr/bin/env bash

set -eox

export TARGET="linux-glibc"
export FLAGS="USE_ZLIB=1 USE_PCRE=1 USE_PCRE_JIT=1 USE_LUA=1 USE_OPENSSL=1 USE_SYSTEMD=1 USE_DEVICEATLAS=1 DEVICEATLAS_SRC=contrib/deviceatlas USE_51DEGREES=1"
export OPENSSL_VERSION="1.1.1f"
export SSL_LIB=${HOME}/opt/lib
export SSL_INC=${HOME}/opt/include
export TMPDIR=/tmp
export FIFTYONEDEGREES_SRC="contrib/51d/src/pattern"
export DEBUG_OPTIONS="DEBUG_STRICT=1"
export CC=clang-9

git clone --depth=1 https://github.com/VTest/VTest.git /vtest

pushd /haproxy
make clean 
make -C /vtest FLAGS="-O2 -s -Wall"
bash ./scripts/build-ssl.sh

if [ "${CC%-*}"  = "clang" ]; then 
    export FLAGS="$FLAGS USE_OBSOLETE_LINKER=1" 
    export DEBUG_CFLAGS="-g" # -fsanitize=address"  # 
    # Sanitizer fails with:
    # ==26239==LeakSanitizer has encountered a fatal error.
    # ==26239==HINT: For debugging, try setting environment variable LSAN_OPTIONS=verbosity=1:log_threads=1
    # ==26239==HINT: LeakSanitizer does not work under ptrace (strace, gdb, etc)
    # export LDFLAGS="-fsanitize=address"
fi

make -j3 CC=$CC V=0 ERR=1 TARGET=$TARGET $FLAGS DEBUG_CFLAGS="$DEBUG_CFLAGS" LDFLAGS="$LDFLAGS" ADDLIB="-Wl,-rpath,$SSL_LIB" 51DEGREES_SRC="$FIFTYONEDEGREES_SRC" EXTRA_OBJS="$EXTRA_OBJS" $DEBUG_OPTIONS

./haproxy -vv
ldd haproxy

make reg-tests VTEST_PROGRAM=/vtest/vtest REGTESTS_TYPES=default,bug,devel

for folder in ${TMPDIR}/*regtest*/vtc.*; do
    cat $folder/INFO
    cat $folder/LOG
done

popd