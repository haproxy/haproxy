#!/bin/sh
set -eux

download_openssl () {
    if [ ! -f "download-cache/openssl-${OPENSSL_VERSION}.tar.gz" ]; then
        wget -P download-cache/ \
            "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
    fi
}

build_openssl_linux () {
    (
        cd "openssl-${OPENSSL_VERSION}/"
        ./config shared --prefix="${HOME}/opt" --openssldir="${HOME}/opt" -DPURIFY
        make all install_sw
    )
}

build_openssl_osx () {
    (
        cd "openssl-${OPENSSL_VERSION}/"
        ./Configure darwin64-x86_64-cc shared \
            --prefix="${HOME}/opt" --openssldir="${HOME}/opt" -DPURIFY
        make depend all install_sw
    )
}

build_openssl () {
    if [ "$(cat ${HOME}/opt/.openssl-version)" != "${OPENSSL_VERSION}" ]; then
        tar zxf "download-cache/openssl-${OPENSSL_VERSION}.tar.gz"
        if [ "${TRAVIS_OS_NAME}" = "osx" ]; then
            build_openssl_osx
        elif [ "${TRAVIS_OS_NAME}" = "linux" ]; then
            build_openssl_linux
        fi
        echo "${OPENSSL_VERSION}" > "${HOME}/opt/.openssl-version"
    fi
}

download_libressl () {
    if [ ! -f "download-cache/libressl-${LIBRESSL_VERSION}.tar.gz" ]; then
        wget -P download-cache/ \
	    "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VERSION}.tar.gz"
    fi
}

build_libressl () {
    if [ "$(cat ${HOME}/opt/.libressl-version)" != "${LIBRESSL_VERSION}" ]; then
        tar zxf "download-cache/libressl-${LIBRESSL_VERSION}.tar.gz"
        (
           cd "libressl-${LIBRESSL_VERSION}/"
           ./configure --prefix="${HOME}/opt"
            make all install
        )
        echo "${LIBRESSL_VERSION}" > "${HOME}/opt/.libressl-version"
    fi
}

download_boringssl () {
    if [ ! -d "download-cache/boringssl" ]; then
        git clone --depth=1 https://boringssl.googlesource.com/boringssl download-cache/boringssl
    else
       (
        cd download-cache/boringssl
        git pull
       )
    fi
}

if [ ! -z ${LIBRESSL_VERSION+x} ]; then
	download_libressl
	build_libressl
fi

if [ ! -z ${OPENSSL_VERSION+x} ]; then
	download_openssl
	build_openssl
fi

if [ ! -z ${BORINGSSL+x} ]; then
	(

	# travis-ci comes with go-1.11, while boringssl requires go-1.13
	eval "$(curl -sL https://raw.githubusercontent.com/travis-ci/gimme/master/gimme | GIMME_GO_VERSION=1.13 bash)"

        download_boringssl
	cd download-cache/boringssl
        if [ -d build ]; then rm -rf build; fi
	mkdir build
	cd build
	cmake -DCMAKE_BUILD_TYPE=release -DBUILD_SHARED_LIBS=1 ..
	make

	rm -rf ${SSL_LIB} || exit 0
	rm -rf ${SSL_INC} || exit 0

	mkdir -p ${SSL_LIB}
	cp crypto/libcrypto.so ssl/libssl.so ${SSL_LIB}

	mkdir -p ${SSL_INC}
	cp -r ../include/* ${SSL_INC}
	)
fi

