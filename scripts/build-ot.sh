#!/bin/bash

#
# OT helper. script built from documentation: https://github.com/haproxytech/opentracing-c-wrapper
#

set -e

OT_CPP_VERSION="${OT_CPP_VERSION:-1.6.0}"
OT_PREFIX="${OT_PREFIX:-${HOME}/opt}"

wget -P download-cache/ "https://github.com/opentracing/opentracing-cpp/archive/v${OT_CPP_VERSION}.tar.gz"

tar xf download-cache/v${OT_CPP_VERSION}.tar.gz
cd opentracing-cpp-${OT_CPP_VERSION}
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=${OT_PREFIX} -DBUILD_STATIC_LIBS=OFF -DBUILD_MOCKTRACER=OFF -DBUILD_TESTING=OFF ..
make -j$(nproc)
make install

git clone https://github.com/haproxytech/opentracing-c-wrapper.git
cd opentracing-c-wrapper
 ./scripts/bootstrap
 ./configure --prefix=${OT_PREFIX} --with-opentracing=${OT_PREFIX}
 make -j$(nproc)
 make install
