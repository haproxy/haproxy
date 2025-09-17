#!/bin/sh
#
# Download curl and compile it with ECH
#
set -eux

CURL_DESTDIR=${CURL_DESTDIR:-${HOME}/opt}
CURL_TMPDIR=${CURL_TMPDIR:-/tmp/download-cache}
SSL_LIB=${SSL_LIB:-}
CURL_VERSION=git-master

SSL_OPT=--with-openssl
SSL_LDFLAGS=


curl_download() {
	cd "${CURL_TMPDIR}"
	# update the curl version using the commit ID of the branch HEAD
	branch_name="${CURL_VERSION##git-}"
	CURL_VERSION=git-$(wget -q -O- "https://api.github.com/repos/curl/curl/branches/$branch_name" | grep '"sha":' | head -n 1 | sed -E 's/ *"sha": "(.*)",/\1/')
	wget -q -O "${CURL_TMPDIR}/curl-${CURL_VERSION}.tar.gz" \
	     "https://github.com/curl/curl/archive/${CURL_VERSION##git-}.tar.gz"
}

curl_build() {
	if [ -n "$SSL_LIB" ]; then
		SSL_LDFLAGS="-Wl,-rpath,${SSL_LIB}/lib"
		SSL_OPT="--with-ssl=${SSL_LIB}"
	fi

	cd "${CURL_TMPDIR}"
	mkdir -p "${CURL_TMPDIR}/curl-${CURL_VERSION}"
	tar zxf "${CURL_TMPDIR}/curl-${CURL_VERSION}.tar.gz" -C "${CURL_TMPDIR}/curl-${CURL_VERSION}/" --strip-components=1
	cd "${CURL_TMPDIR}/curl-${CURL_VERSION}"

	autoreconf -fi
	LDFLAGS=${SSL_LDFLAGS} ./configure "${SSL_OPT}" --prefix="${CURL_DESTDIR}" --enable-ech
	make -j"$(nproc)"
	make install
	echo "${CURL_VERSION}" > "${CURL_DESTDIR}/.curl-version"
}


mkdir -p "${CURL_DESTDIR}"
mkdir -p "${CURL_TMPDIR}"

curl_download
curl_build
