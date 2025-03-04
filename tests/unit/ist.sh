#!/bin/sh

check() {
:
}


run() {
	 gcc -Iinclude -Wall -W -fomit-frame-pointer -Os ${ROOTDIR}/tests/unit/ist.c -o ${ROOTDIR}/tests/unit/istOs
	 ${ROOTDIR}/tests/unit/istOs > /dev/null
	 gcc -Iinclude -Wall -W -fomit-frame-pointer -O1 ${ROOTDIR}/tests/unit/ist.c -o ${ROOTDIR}/tests/unit/istO1
	 ${ROOTDIR}/tests/unit/istO1 > /dev/null
	 gcc -Iinclude -Wall -W -fomit-frame-pointer -O2 ${ROOTDIR}/tests/unit/ist.c -o ${ROOTDIR}/tests/unit/istO2
	 ${ROOTDIR}/tests/unit/istO2 > /dev/null
	 gcc -Iinclude -Wall -W -fomit-frame-pointer -O3 ${ROOTDIR}/tests/unit/ist.c -o ${ROOTDIR}/tests/unit/istO3
	 ${ROOTDIR}/tests/unit/istO3 > /dev/null

	 rm ${ROOTDIR}/tests/unit/istOs
	 rm ${ROOTDIR}/tests/unit/istO1
	 rm ${ROOTDIR}/tests/unit/istO2
	 rm ${ROOTDIR}/tests/unit/istO3
}

case "$1" in
	"check")
		check
	;;
	"run")
		run
	;;
esac
