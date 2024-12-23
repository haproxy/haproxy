#!/bin/sh
set -eux

BUILDSSL_DESTDIR=${BUILDSSL_DESTDIR:-${HOME}/opt}
BUILDSSL_TMPDIR=${BUILDSSL_TMPDIR:-/tmp/download-cache}

WOLFSSL_DEBUG=${WOLFSSL_DEBUG:-0}

download_openssl () {
    if [ ! -f "${BUILDSSL_TMPDIR}/openssl-${OPENSSL_VERSION}.tar.gz" ]; then

#
# OpenSSL has different links for latest and previous releases
# since we want to download several versions, let us try to treat
# current version as latest, if it fails, follow with previous
#

	wget -P ${BUILDSSL_TMPDIR}/ \
	    "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" || \
        wget -P ${BUILDSSL_TMPDIR}/ \
            "https://www.openssl.org/source/old/${OPENSSL_VERSION%[a-z]}/openssl-${OPENSSL_VERSION}.tar.gz" || \
	wget -P ${BUILDSSL_TMPDIR}/ \
	    "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
    fi
}

# recent openssl versions support parallel builds and skipping the docs,
# while older ones require to build everything sequentially.
build_openssl_linux () {
    (
        cd "${BUILDSSL_TMPDIR}/openssl-${OPENSSL_VERSION}/"
        ./config shared --prefix="${BUILDSSL_DESTDIR}" --openssldir="${BUILDSSL_DESTDIR}" --libdir=lib -DPURIFY
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
        cd "${BUILDSSL_TMPDIR}/openssl-${OPENSSL_VERSION}/"
        ./Configure darwin64-x86_64-cc shared \
            --prefix="${BUILDSSL_DESTDIR}" --openssldir="${BUILDSSL_DESTDIR}" --libdir=lib -DPURIFY
        make depend build_sw install_sw
    )
}

build_openssl () {
    if [ "$(cat ${BUILDSSL_DESTDIR}/.openssl-version)" != "${OPENSSL_VERSION}" ]; then

	mkdir -p "${BUILDSSL_TMPDIR}/openssl-${OPENSSL_VERSION}/"
	tar zxf "${BUILDSSL_TMPDIR}/openssl-${OPENSSL_VERSION}.tar.gz" -C "${BUILDSSL_TMPDIR}/openssl-${OPENSSL_VERSION}/" --strip-components=1
	case `uname` in
		'Darwin')
			build_openssl_osx
			;;
		'Linux')
			build_openssl_linux
			;;
		*)
                        echo "not yet implemented"
                        exit 1
			;;
	esac
        echo "${OPENSSL_VERSION}" > "${BUILDSSL_DESTDIR}/.openssl-version"
    fi
}

download_libressl () {
    if [ ! -f "${BUILDSSL_TMPDIR}/libressl-${LIBRESSL_VERSION}.tar.gz" ]; then
        wget -P ${BUILDSSL_TMPDIR}/ \
	    "https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VERSION}.tar.gz"
    fi
}

build_libressl () {
    if [ "$(cat ${BUILDSSL_DESTDIR}/.libressl-version)" != "${LIBRESSL_VERSION}" ]; then
        mkdir -p "${BUILDSSL_TMPDIR}/libressl-${LIBRESSL_VERSION}/"
        tar zxf "${BUILDSSL_TMPDIR}/libressl-${LIBRESSL_VERSION}.tar.gz" -C "${BUILDSSL_TMPDIR}/libressl-${LIBRESSL_VERSION}/" --strip-components=1
        (
           cd "${BUILDSSL_TMPDIR}/libressl-${LIBRESSL_VERSION}/"
           ./configure --prefix="${BUILDSSL_DESTDIR}"
            make all install
        )
        echo "${LIBRESSL_VERSION}" > "${BUILDSSL_DESTDIR}/.libressl-version"
    fi
}

download_boringssl () {

    # travis-ci comes with go-1.11, while boringssl requires go-1.13
    eval "$(curl -sL https://raw.githubusercontent.com/travis-ci/gimme/master/gimme | GIMME_GO_VERSION=1.13 bash)"

    if [ ! -d "${BUILDSSL_TMPDIR}/boringssl" ]; then
        git clone --depth=1 https://boringssl.googlesource.com/boringssl ${BUILDSSL_TMPDIR}/boringssl
    else
       (
        cd ${BUILDSSL_TMPDIR}/boringssl
        git pull
       )
    fi
}

build_boringssl () {
	cd ${BUILDSSL_TMPDIR}/boringssl
        if [ -d build ]; then rm -rf build; fi
	mkdir build
	cd build
	cmake  -GNinja -DCMAKE_BUILD_TYPE=release -DBUILD_SHARED_LIBS=1 ..
	ninja

	rm -rf ${BUILDSSL_DESTDIR}/lib || exit 0
	rm -rf ${BUILDSSL_DESTDIR}/include || exit 0

	mkdir -p ${BUILDSSL_DESTDIR}/lib
	cp crypto/libcrypto.so ssl/libssl.so ${BUILDSSL_DESTDIR}/lib

	mkdir -p ${BUILDSSL_DESTDIR}/include
	cp -r ../include/* ${BUILDSSL_DESTDIR}/include
}

download_aws_lc () {
    if [ ! -f "${BUILDSSL_TMPDIR}/aws-lc-${AWS_LC_VERSION}.tar.gz" ]; then
        mkdir -p "${BUILDSSL_TMPDIR}"
        wget -q -O "${BUILDSSL_TMPDIR}/aws-lc-${AWS_LC_VERSION}.tar.gz" \
          "https://github.com/aws/aws-lc/archive/refs/tags/v${AWS_LC_VERSION}.tar.gz"
    fi
}

build_aws_lc () {
    if [ "$(cat ${BUILDSSL_DESTDIR}/.aws_lc-version)" != "${AWS_LC_VERSION}" ]; then
        mkdir -p "${BUILDSSL_TMPDIR}/aws-lc-${AWS_LC_VERSION}/"
        tar zxf "${BUILDSSL_TMPDIR}/aws-lc-${AWS_LC_VERSION}.tar.gz" -C "${BUILDSSL_TMPDIR}/aws-lc-${AWS_LC_VERSION}/" --strip-components=1
        (
           cd "${BUILDSSL_TMPDIR}/aws-lc-${AWS_LC_VERSION}/"
           mkdir -p build
           cd build
           cmake -version
           cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=1 -DDISABLE_GO=1 -DDISABLE_PERL=1 \
             -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=${BUILDSSL_DESTDIR} ..
           make -j$(nproc)
           make install
        )
        echo "${AWS_LC_VERSION}" > "${BUILDSSL_DESTDIR}/.aws_lc-version"
    fi
}

download_aws_lc_fips () {
    if [ ! -f "${BUILDSSL_TMPDIR}/aws-lc-${AWS_LC_FIPS_VERSION}.tar.gz" ]; then
        mkdir -p "${BUILDSSL_TMPDIR}"
        wget -q -O "${BUILDSSL_TMPDIR}/aws-lc-fips-${AWS_LC_FIPS_VERSION}.tar.gz" \
          "https://github.com/aws/aws-lc/archive/refs/tags/AWS-LC-FIPS-${AWS_LC_FIPS_VERSION}.tar.gz"
    fi
}


# require GO + Perl for FIPS mode
build_aws_lc_fips () {
    if [ "$(cat ${BUILDSSL_DESTDIR}/.aws_lc_fips-version)" != "${AWS_LC_FIPS_VERSION}" ]; then
        mkdir -p "${BUILDSSL_TMPDIR}/aws-lc-fips-${AWS_LC_FIPS_VERSION}/"
        tar zxf "${BUILDSSL_TMPDIR}/aws-lc-fips-${AWS_LC_FIPS_VERSION}.tar.gz" -C "${BUILDSSL_TMPDIR}/aws-lc-fips-${AWS_LC_FIPS_VERSION}/" --strip-components=1
        (
           cd "${BUILDSSL_TMPDIR}/aws-lc-fips-${AWS_LC_FIPS_VERSION}/"
           mkdir -p build
           cd build
           cmake -version
           cmake -DCMAKE_BUILD_TYPE=Release -DFIPS=1 -DBUILD_SHARED_LIBS=1 \
             -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=${BUILDSSL_DESTDIR} ..
           make -j$(nproc)
           make install
        )
        echo "${AWS_LC_FIPS_VERSION}" > "${BUILDSSL_DESTDIR}/.aws_lc_fips-version"
    fi
}

download_quictls () {
    if [ ! -d "${BUILDSSL_TMPDIR}/quictls" ]; then
        git clone --depth=1 https://github.com/quictls/openssl ${BUILDSSL_TMPDIR}/quictls
    else
       (
        cd ${BUILDSSL_TMPDIR}/quictls
        git pull
       )
    fi
}

build_quictls () {
    cd ${BUILDSSL_TMPDIR}/quictls
    ./config shared no-tests ${QUICTLS_EXTRA_ARGS:-} --prefix="${BUILDSSL_DESTDIR}" --openssldir="${BUILDSSL_DESTDIR}" --libdir=lib -DPURIFY
    make -j$(nproc) build_sw
    make install_sw
}

download_wolfssl () {
    if [ ! -f "${BUILDSSL_TMPDIR}/wolfssl-${WOLFSSL_VERSION}.tar.gz" ]; then
      mkdir -p ${BUILDSSL_TMPDIR}
      if [ "${WOLFSSL_VERSION%%-*}" != "git" ]; then
        wget -q -O "${BUILDSSL_TMPDIR}/wolfssl-${WOLFSSL_VERSION}.tar.gz" \
             "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${WOLFSSL_VERSION}-stable.tar.gz"
      else
        wget -q -O "${BUILDSSL_TMPDIR}/wolfssl-${WOLFSSL_VERSION}.tar.gz" \
             "https://github.com/wolfSSL/wolfssl/archive/${WOLFSSL_VERSION##git-}.tar.gz"
      fi
    fi
}

build_wolfssl () {
    if [ "$(cat ${BUILDSSL_DESTDIR}/.wolfssl-version)" != "${WOLFSSL_VERSION}" ]; then
        mkdir -p "${BUILDSSL_TMPDIR}/wolfssl-${WOLFSSL_VERSION}/"
        tar zxf "${BUILDSSL_TMPDIR}/wolfssl-${WOLFSSL_VERSION}.tar.gz" -C "${BUILDSSL_TMPDIR}/wolfssl-${WOLFSSL_VERSION}/" --strip-components=1
        if [ "${WOLFSSL_DEBUG}" -eq 1 ]; then
          WOLFSSL_DEBUG="--enable-debug"
        else
          WOLFSSL_DEBUG=
        fi
        (

           cd "${BUILDSSL_TMPDIR}/wolfssl-${WOLFSSL_VERSION}/"
            autoreconf -i
           ./configure --enable-haproxy --enable-quic --prefix="${BUILDSSL_DESTDIR}" ${WOLFSSL_DEBUG}
           make -j$(nproc)
           make install
        )
        echo "${WOLFSSL_VERSION}" > "${BUILDSSL_DESTDIR}/.wolfssl-version"
    fi
}

mkdir -p "${BUILDSSL_DESTDIR}"


if [ ! -z ${LIBRESSL_VERSION+x} ]; then
	download_libressl
	build_libressl
fi

if [ ! -z ${OPENSSL_VERSION+x} ]; then
	download_openssl
	build_openssl
fi

if [ ! -z ${BORINGSSL+x} ]; then
    download_boringssl
    build_boringssl
fi

if [ ! -z ${AWS_LC_VERSION+x} ]; then
	download_aws_lc
  build_aws_lc
fi

if [ ! -z ${AWS_LC_FIPS_VERSION+x} ]; then
	download_aws_lc_fips
	build_aws_lc_fips
fi

if [ ! -z ${QUICTLS+x} ]; then
        download_quictls
        build_quictls
fi

if [ ! -z ${WOLFSSL_VERSION+x} ]; then
	download_wolfssl
	build_wolfssl
fi
