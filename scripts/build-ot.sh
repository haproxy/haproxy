#!/bin/bash

#
# OT helper. script built from documentation: https://github.com/haproxytech/opentracing-c-wrapper
#

set -e

export OT_CPP_VERSION=1.5.0

if [ ! -f "download-cache/v${OT_CPP_VERSION}.tar.gz" ]; then
    wget -P download-cache/ \
        "https://github.com/opentracing/opentracing-cpp/archive/v${OT_CPP_VERSION}.tar.gz"
fi

if [ "$(cat ${HOME}/opt/.ot-cpp-version)" != "${OT_CPP_VERSION}" ]; then
    tar xf download-cache/v${OT_CPP_VERSION}.tar.gz
    cd opentracing-cpp-${OT_CPP_VERSION}
    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX=${HOME}/opt -DBUILD_STATIC_LIBS=OFF -DBUILD_MOCKTRACER=OFF -DBUILD_TESTING=OFF ..
    make
    make install
    echo "${OT_CPP_VERSION}" > "${HOME}/opt/.ot-cpp-version"
fi

git clone https://github.com/haproxytech/opentracing-c-wrapper.git
cd opentracing-c-wrapper
 ./scripts/bootstrap
 ./configure --prefix=${HOME}/opt --with-opentracing=${HOME}/opt
 make
 make install


