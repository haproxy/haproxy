#!/bin/sh

check() {
	${HAPROXY_PROGRAM} -vv | grep CFLAGS | grep -q "fsanitize=address"
}

run() {
	${HAPROXY_PROGRAM} -dI -f ${ROOTDIR}/.github/h2spec.config -c
	${HAPROXY_PROGRAM} -dI -f ${ROOTDIR}/examples/content-sw-sample.cfg -c
	${HAPROXY_PROGRAM} -dI -f ${ROOTDIR}/examples/option-http_proxy.cfg -c
	${HAPROXY_PROGRAM} -dI -f ${ROOTDIR}/examples/quick-test.cfg -c
	${HAPROXY_PROGRAM} -dI -f ${ROOTDIR}/examples/transparent_proxy.cfg -c
}

case "$1" in
	"check")
		check
	;;
	"run")
		run
	;;
esac
