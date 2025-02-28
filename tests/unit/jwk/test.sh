#!/bin/sh

check() {
	${HAPROXY_PROGRAM} -vv | grep -E '^Unit tests list :' | grep -q "jwk"
}

run() {
	FILE1=$(mktemp)
	${HAPROXY_PROGRAM} -U jwk ${TESTDIR}/ecdsa.key > "${FILE1}"
	diff -Naurp ${TESTDIR}/ecdsa.pub.jwk "${FILE1}"
	rm "${FILE1}"

	FILE2=$(mktemp)
	${HAPROXY_PROGRAM} -U jwk ${TESTDIR}/rsa.key > "${FILE2}"
	diff -Naurp ${TESTDIR}/rsa.pub.jwk "${FILE2}"
	rm "${FILE2}"
}

case "$1" in
	"check")
		check
	;;
	"run")
		run
	;;
esac
