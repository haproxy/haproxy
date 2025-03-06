#!/bin/sh

export HAPROXY_PROGRAM="${HAPROXY_PROGRAM:-${PWD}/haproxy}"
export HAPROXY_ARGS="${HAPROXY_ARGS--dM -dI -dW}"
export ROOTDIR="${ROOTDIR:-${PWD}}"
export TESTDIR="${TESTDIR:-./tests/unit/}"

result=0

echo ""
echo "########################## Preparing to run unit tests ##########################"

preparefailed=
if ! [ -x "$(command -v $HAPROXY_PROGRAM)" ]; then
	echo "haproxy not found in path, please specify HAPROXY_PROGRAM environment variable"
	preparefailed=1
fi
if [ $preparefailed ]; then
	exit 1
fi

{ read HAPROXY_VERSION; read TARGET; read FEATURES; read SERVICES; } << EOF
$($HAPROXY_PROGRAM $HAPROXY_ARGS -vv | grep -E 'HA-?Proxy version|TARGET.*=|^Feature|^Available services' | sed 's/.* [:=] //')
EOF

UNITTESTS=$($HAPROXY_PROGRAM $HAPROXY_ARGS -vv|grep -E '^Unit tests list' | sed 's/.* [:=] //')
if [ -z "$UNITTESTS" ]; then
	UNITTESTS="none"
fi

HAPROXY_VERSION=$(echo $HAPROXY_VERSION | cut -d " " -f 3)
echo "Testing with haproxy version: $HAPROXY_VERSION"

PROJECT_VERSION=$(${MAKE:-make} version 2>&1 | grep -E '^VERSION:|^SUBVERS:'|cut -f2 -d' '|tr -d '\012')
if [ -z "${PROJECT_VERSION}${MAKE}" ]; then
	# try again with gmake, just in case
	PROJECT_VERSION=$(gmake version 2>&1 | grep -E '^VERSION:|^SUBVERS:'|cut -f2 -d' '|tr -d '\012')
fi
FEATURES_PATTERN=" $FEATURES "
SERVICES_PATTERN=" $SERVICES "

echo "Target : $TARGET"
echo "Options : $FEATURES"
echo "Services : $SERVICES"
echo "Unit tests: $UNITTESTS"

succeed=0
failed=0
skipped=0
testlist=

echo "########################## Gathering tests to run ##########################"

for test in $(find "$TESTDIR" -name "*.sh"); do
	sh -e ${test} check 2>&1 1>/dev/null
	r="$?"
	if [ "$r" = "0" ]; then
		echo "  Add test: $test"
		testlist="$testlist $test"
	else
		skipped=$((skipped+1))
		echo "  Skip $test"
	fi
done

echo "########################## Starting unit tests ##########################"

for TEST in $testlist; do
#	echo "*** run ${TEST}"
	export TEST
	export TESTDIR=`dirname ${TEST}`

	sh -e ${TEST} run 2>&1 1>/dev/null
	r="$?"
	if [ "$r" != "0" ]; then
		echo "Test ${TEST} failed: $r"
		result=$r
		failed=$((failed+1))
	else
		succeed=$((succeed+1))
	fi
done

echo "${failed} tests failed, ${skipped} tests skipped, ${succeed} tests passed"

exit $result
