#!/bin/sh
set -eux

download_openssl () {
    if [ ! -f "download-cache/openssl-${OPENSSL_VERSION}.tar.gz" ]; then

#
# OpenSSL has different links for latest and previous releases
# since we want to download several versions, let us try to treat
# current version as latest, if it fails, follow with previous
#

	wget -P download-cache/ \
	    "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" || \
        wget -P download-cache/ \
            "https://www.openssl.org/source/old/${OPENSSL_VERSION%[a-z]}/openssl-${OPENSSL_VERSION}.tar.gz"
    fi
}

# recent openssl versions support parallel builds and skipping the docs,
# while older ones require to build everything sequentially.
build_openssl_linux () {
    (
        cd "openssl-${OPENSSL_VERSION}/"
        ./config shared --prefix="${HOME}/opt" --openssldir="${HOME}/opt" --libdir=lib -DPURIFY
        if [ -z "${OPENSSL_VERSION##1.*}" ]; then
            make all
        else
            make -j$(nproc) build_sw
        fi
        make install_sw
    )
}

build_openssl_osx () {
    (
        cd "openssl-${OPENSSL_VERSION}/"
        ./Configure darwin64-x86_64-cc shared \
            --prefix="${HOME}/opt" --openssldir="${HOME}/opt" --libdir=lib -DPURIFY
        make depend build_sw install_sw
    )
}

build_openssl () {
    if [ "$(cat ${HOME}/opt/.openssl-version)" != "${OPENSSL_VERSION}" ]; then
        tar zxf "download-cache/openssl-${OPENSSL_VERSION}.tar.gz"
	case `uname` in
		'Darwin')
			build_openssl_osx
			;;
		'Linux')
			build_openssl_linux
			;;
	esac
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

download_quictls () {
    if [ ! -d "download-cache/quictls" ]; then
        git clone --depth=1 https://github.com/quictls/openssl download-cache/quictls
    else
       (
        cd download-cache/quictls
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
	cmake  -GNinja -DCMAKE_BUILD_TYPE=release -DBUILD_SHARED_LIBS=1 ..
	ninja

	rm -rf ${HOME}/opt/lib || exit 0
	rm -rf ${HOME}/opt/include || exit 0

	mkdir -p ${HOME}/opt/lib
	cp crypto/libcrypto.so ssl/libssl.so ${HOME}/opt/lib

	mkdir -p ${HOME}/opt/include
	cp -r ../include/* ${HOME}/opt/include
	)
fi

if [ ! -z ${QUICTLS+x} ]; then
        (

        download_quictls
        cd download-cache/quictls

        ./config shared --prefix="${HOME}/opt" --openssldir="${HOME}/opt" --libdir=lib -DPURIFY
        make -j$(nproc) build_sw
        make install_sw

        )
fi
