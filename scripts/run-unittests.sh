#!/bin/sh

export HAPROXY_PROGRAM="${HAPROXY_PROGRAM:-${PWD}/haproxy}"
export HAPROXY_ARGS="${HAPROXY_ARGS--dM -dI -dW}"
export ROOTDIR="${ROOTDIR:-${PWD}}"
export TESTDIR="${TESTDIR:-./tests/unit/}"
export TMPDIR="${TMPDIR:-/tmp}"

result=0

echo ""
echo "########################## Preparing to run unit tests ##########################"

if ! [ -x "$(command -v $HAPROXY_PROGRAM)" ]; then
	echo "haproxy not found in path, please specify HAPROXY_PROGRAM environment variable"
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

TESTRUNDATETIME="$(date '+%Y-%m-%d_%H-%M-%S')"
DSTDIR=$(mktemp -d "${TMPDIR}/ha-unittests-$TESTRUNDATETIME.XXXXXX") || exit 1
mkdir -p "${DSTDIR}" || exit 1
mkdir -p "${DSTDIR}/results/" || exit 1

echo "########################## Gathering tests to run ##########################"

for test in $(find "${TESTDIR}" -name "*.sh"); do
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
	export TESTDIR=$( dirname ${TEST} )
	RESULTFILE=$( mktemp "${DSTDIR}/results/res.XXXXXX" )
	touch "${RESULTFILE}" || exit 1

	echo "${TEST}" > "${RESULTFILE}"
	sh -x -e "${TEST}" run 1>>"${RESULTFILE}" 2>&1
	r="$?"
	if [ "$r" != "0" ]; then
		echo "  Test ${TEST} failed: $r"
		result=$r
		failed=$((failed+1))
	else
		succeed=$((succeed+1))
		rm "${RESULTFILE}"
	fi
done

echo "${failed} tests failed, ${skipped} tests skipped, ${succeed} tests passed"

exit $result
