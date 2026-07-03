#!/bin/sh

_help()
{
  cat << EOF
### run-regtests.sh ###
  Running run-regtests.sh --help shows this information about how to use it

  Run without parameters to run all tests in the current folder (including subfolders)
    run-regtests.sh

  Provide paths to run tests from (including subfolders):
    run-regtests.sh ./tests1 ./tests2

  Parameters:
    --j <NUM>, To run vtest with multiple jobs / threads for a faster overall result
      run-regtests.sh ./fasttest --j 16

    --v, to run verbose
      run-regtests.sh --v, disables the default vtest 'quiet' parameter

    --debug to show test logs on standard output (implies --v)
      run-regtests.sh --debug

    --keep-logs to keep all log directories (by default kept if test fails)
      run-regtests.sh --keep-logs

    --vtestparams <ARGS>, passes custom ARGS to vtest
      run-regtests.sh --vtestparams "-n 10"

    --type <reg tests types> filter the types of the tests to be run, depending on
      the commented REGTESTS_TYPE variable value in each VTC file.
      The value of REGTESTS_TYPE supported are: default, slow, bug, broken, devel
      and experimental. When not specified, it is set to 'default' as default value.

      run-regtest.sh --type slow,default

    --clean to cleanup previous reg-tests log directories and exit
      run-regtests.sh --clean

  Including text below into a .vtc file will check for its requirements
  related to haproxy's target and compilation options
    # Below targets are not capable of completing this test successfully
    #EXCLUDE_TARGET=freebsd, abns sockets are not available on freebsd

    #EXCLUDE_TARGETS=dos,freebsd,windows

  Configure environment variables to set the haproxy and vtest binaries to use
    setenv HAPROXY_PROGRAM /usr/local/sbin/haproxy
    setenv VTEST_PROGRAM /usr/local/bin/vtest
    setenv HAPROXY_ARGS "-dM -de -m 50"
  or
    export HAPROXY_PROGRAM=/usr/local/sbin/haproxy
    export VTEST_PROGRAM=/usr/local/bin/vtest
    export HAPROXY_ARGS="-dM -de -m 50"
EOF
  exit 0
}

_startswith() {
  _str="$1"
  _sub="$2"
  echo "$_str" | grep "^$_sub" >/dev/null 2>&1
}

_findtests() {
  set -f

  REGTESTS_TYPES="${REGTESTS_TYPES:-default,bug,devel,slow}"
  any_test=$(echo $REGTESTS_TYPES | grep -cw "any")
  for i in $( find "$1" -name *.vtc ); do
    skiptest=
    OLDIFS="$IFS"; IFS="$LINEFEED"
    set -- $(grep '^#[0-9A-Z_]*=' "$i")
    IFS="$OLDIFS"

    exclude_targets=""; regtest_type=""; excludedtarget=""

    while [ $# -gt 0 ]; do
      v="$1"; v="${v#*=}"
      case "$1" in
        "#EXCLUDE_TARGETS="*)       exclude_targets="$v" ;;
        "#REGTEST_TYPE="*)          regtest_type="$v" ;;
        "#EXCLUDE_TARGET="*)        excludedtarget="${v%,*}" ;;
        # Note: any new variable declared here must be initialized above.
      esac
      shift
    done

    if [ $any_test -ne 1 ] ; then
        if [ -z $regtest_type ] ; then
            regtest_type=default
        fi
        if ! $(echo $REGTESTS_TYPES | grep -wq $regtest_type) ; then
            echo "  Skipped $i because its type '"$regtest_type"' is excluded" >> "${TESTDIR}/skipped.log"
            skiptest=1
        fi
    fi

    if [ -n "$excludedtarget" ]; then
      exclude_targets="$exclude_targets,$excludedtarget"
    fi

    IFS=","; set -- $exclude_targets;  IFS=$OLDIFS; exclude_targets="$*"

    for excludedtarget in $exclude_targets; do
      if [ "$excludedtarget" = "$TARGET" ]; then
        echo "  Skipped $i because haproxy is compiled for the excluded target $TARGET" >> "${TESTDIR}/skipped.log"
        skiptest=1
      fi
    done

    if [ -z $skiptest ]; then
      echo "  Add test: $i"
      testlist="$testlist $i"
    fi
  done
}

_cleanup()
{
  DIRS=$(find "${TESTDIR}" -maxdepth 1 -type d -name "haregtests-*" -exec basename {} \; 2>/dev/null)
  if [ -z "${DIRS}" ]; then
    echo "No reg-tests log directory found"
  else
    echo "Cleanup following reg-tests log directories:"
    for d in ${DIRS}; do
      echo  "    o ${TESTDIR}/$d"
    done
    read -p "Continue (y/n)?" reply
    case "$reply" in
      y|Y)
        for d in ${DIRS}; do
          rm -r "${TESTDIR}/$d"
        done
        echo "done"
        exit 0
        ;;
       *)
        echo "aborted"
        exit 1
        ;;
    esac
  fi
}


_process() {
  while [ ${#} -gt 0 ]; do
    if _startswith "$1" "-"; then
      case "${1}" in
        --j)
          jobcount="$2"
          shift
          ;;
        --vtestparams)
          vtestparams="$2"
          shift
          ;;
        --v)
          verbose=""
          ;;
        --debug)
          verbose=""
          debug="-v"
          ;;
        --keep-logs)
          keep_logs=1
          ;;
        --type)
	      REGTESTS_TYPES="$2"
	      shift
	      ;;
        --clean)
          _cleanup
          exit 0
          ;;
        --help)
          _help
          ;;
        *)
          echo "Unknown parameter : $1"
          exit 1
          ;;
      esac
    else
      REGTESTS="${REGTESTS} $1"
    fi
    shift 1
  done
}


HAPROXY_PROGRAM="${HAPROXY_PROGRAM:-${PWD}/haproxy}"
HAPROXY_ARGS="${HAPROXY_ARGS--dM -dI -dW}"
VTEST_PROGRAM="${VTEST_PROGRAM:-vtest}"
VTEST_TIMEOUT="${VTEST_TIMEOUT:-10}"
TESTDIR="${TMPDIR:-/tmp}"
REGTESTS=""
LINEFEED="
"

jobcount=""
verbose="-q"
debug=""
keep_logs=0
testlist=""

_process "$@";

echo ""
echo "########################## Preparing to run tests ##########################"

preparefailed=
if ! [ -x "$(command -v $HAPROXY_PROGRAM)" ]; then
  echo "haproxy not found in path, please specify HAPROXY_PROGRAM environment variable"
  preparefailed=1
fi
if ! [ -x "$(command -v $VTEST_PROGRAM)" ]; then
  echo "vtest not found in path, please specify VTEST_PROGRAM environment variable"
  preparefailed=1
fi
if [ $preparefailed ]; then
  exit 1
fi

{ read HAPROXY_VERSION; read TARGET; } << EOF
$($HAPROXY_PROGRAM $HAPROXY_ARGS -vv | grep -E 'HA-?Proxy version|TARGET.*=' | sed 's/.* [:=] //')
EOF

HAPROXY_VERSION=$(echo $HAPROXY_VERSION | cut -d " " -f 3)
echo "Testing with haproxy version: $HAPROXY_VERSION"

PROJECT_VERSION=$(${MAKE:-make} version 2>&1 | grep -E '^VERSION:|^SUBVERS:'|cut -f2 -d' '|tr -d '\012')
if [ -z "${PROJECT_VERSION}${MAKE}" ]; then
        # try again with gmake, just in case
        PROJECT_VERSION=$(gmake version 2>&1 | grep -E '^VERSION:|^SUBVERS:'|cut -f2 -d' '|tr -d '\012')
fi

TESTRUNDATETIME="$(date '+%Y-%m-%d_%H-%M-%S')"

mkdir -p "$TESTDIR" || exit 1
TESTDIR=$(mktemp -d "$TESTDIR/haregtests-$TESTRUNDATETIME.XXXXXX") || exit 1

export TMPDIR="$TESTDIR"
export HAPROXY_PROGRAM="$HAPROXY_PROGRAM"
if [ -n "$HAPROXY_ARGS" ]; then
   export HAPROXY_ARGS
fi

echo "Target : $TARGET"

echo "########################## Gathering tests to run ##########################"

if [ -z "$REGTESTS" ]; then
  _findtests reg-tests/
else
  for t in $REGTESTS; do
    _findtests $t
  done
fi

echo "########################## Starting vtest ##########################"
echo "Testing with haproxy version: $HAPROXY_VERSION"

if [ -n "$PROJECT_VERSION" -a "$PROJECT_VERSION" != "$HAPROXY_VERSION" ]; then
        echo "Warning: version does not match the current tree ($PROJECT_VERSION)"
fi

_vtresult=0
if [ -n "$testlist" ]; then
  if [ -n "$jobcount" ]; then
    jobcount="-j $jobcount"
  fi
  cmd="$VTEST_PROGRAM -b $((2<<20)) -k -t ${VTEST_TIMEOUT} -L $verbose $debug $jobcount $vtestparams $testlist"
  eval $cmd
  _vtresult=$?
  grep -rE --include="LOG" 'sh: -c: line [0-9]+: syntax error|syntax error near unexpected token|Syntax error' "$TESTDIR"
  if [ $? -eq 0 ]; then
    echo "########################## Fatal shell syntax errors ##########################"
    _vtresult=1
  fi
else
  echo "No tests found that meet the required criteria"
fi

if [ -d "${TESTDIR}" ]; then
  # look for tests skipped by vtest
  find "${TESTDIR}" -type f -name "LOG" | while read logfile; do
    REASON=$(grep "SKIPPING test" "$logfile")
    if [ -n "$REASON" ]; then
      infofile="$(dirname "$logfile")/INFO"
      if [ -e "$infofile" ]; then
        vtc_path=$(sed 's/^Test case: //' "$infofile" )
        if [ -n "$vtc_path" ]; then
          echo "  Skipped $vtc_path (feature cmd)" >> "${TESTDIR}/skipped.log"
        fi
      fi
    fi
  done

  if [ $keep_logs -eq 0 ]; then
    # remove logs for successful tests
    find "$TESTDIR" -type d -name "vtc.*" | while read vtcdir; do
      # errors are starting with ----
      grep -q "^----" ${vtcdir}/LOG || rm -fr "${vtcdir}"
    done
  fi

  if [ $_vtresult -eq 0 ]; then
    # all tests were successful, removing tempdir (the last part.)
    # ignore errors is the directory is not empty or if it does not exist
     rmdir "$TESTDIR" 2>/dev/null
  fi

  # show failed tests
  if [ -d "${TESTDIR}" ]; then
    echo "########################## Gathering results ##########################"
    export TESTDIR
    find "$TESTDIR" -type d -name "vtc.*" -exec sh -c 'for i; do
      if [ ! -e "$i/LOG" ] ; then continue; fi

      cat <<- EOF | tee -a "$TESTDIR/failedtests.log"
$(echo "###### $(cat "$i/INFO") ######")
$(echo "## test results in: \"$i\"")
$(echo "## test log file: $i/LOG")
$(grep -E -- "^(----|\*    diag)" "$i/LOG")
EOF
    done' sh {} +
  fi
    echo "########################## Listing skipped tests ####################"
    count=0
    if [ -e "${TESTDIR}/skipped.log" ]; then
      count=$(wc -l < "${TESTDIR}/skipped.log")
      cat "${TESTDIR}/skipped.log" | sort -n
    fi
    echo "Total skipped tests: $count"

fi # if TESTDIR

exit $_vtresult
