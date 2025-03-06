#!/bin/sh

check() {
# This test depends on the "jose" command tool, we can probably replace it later by the verifying code from jwt.c

	command -v jose
	${HAPROXY_PROGRAM} -vv | grep -E '^Unit tests list :' | grep -q "jws"
}

run() {

	${HAPROXY_PROGRAM} -U jws ${ROOTDIR}/tests/unit/jwk/ecdsa.key '{ "test": "yes" }' "KtFDYsfAgsiquFl9S921hd5K_QbdoqVyPSQ-8r8Ig7ZqOFg_WZQ" "https://haproxy.com" | jose jws ver -i- -k $ROOTDIR/tests/unit/jwk/ecdsa.pub.jwk -O-
	${HAPROXY_PROGRAM} -U jws ${ROOTDIR}/tests/unit/jwk/rsa.key '{ "test": "yes" }' "KtFDYsfAgsiquFl9S921hd5K_QbdoqVyPSQ-8r8Ig7ZqOFg_WZQ" "https://haproxy.com" | jose jws ver -i- -k $ROOTDIR/tests/unit/jwk/rsa.pub.jwk -O-
}

case "$1" in
	"check")
		check
	;;
	"run")
		run
	;;
esac
