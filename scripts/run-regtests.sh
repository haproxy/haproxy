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
    --j <NUM>, To run varnishtest with multiple jobs / threads for a faster overall result
      run-regtests.sh ./fasttest --j 16

    --v, to run verbose
      run-regtests.sh --v, disables the default varnishtest 'quiet' parameter

    --debug to show test logs on standard ouput (implies --v)
      run-regtests.sh --debug

    --keep-logs to keep all log directories (by default kept if test fails)
      run-regtests.sh --keep-logs

    --varnishtestparams <ARGS>, passes custom ARGS to varnishtest
      run-regtests.sh --varnishtestparams "-n 10"

    --clean to cleanup previous reg-tests log directories and exit
      run-regtests.sh --clean

    --use-htx to use the HTX in tests
      run-regtests.sh --use-htx, unsets the macro \${no-htx}
      In .vtc files, in HAProxy configuration, you should use the following line
      to "templatize" your tests:

          \${no-htx} option http-use-htx

  Including text below into a .vtc file will check for its requirements
  related to haproxy's target and compilation options
    # Below targets are not capable of completing this test succesfully
    #EXCLUDE_TARGET=freebsd, abns sockets are not available on freebsd

    #EXCLUDE_TARGETS=dos,freebsd,windows

    # Below option is required to complete this test succesfully
    #REQUIRE_OPTION=OPENSSL, this test needs OPENSSL compiled in.

    #REQUIRE_OPTIONS=ZLIB|SLZ,OPENSSL,LUA

    # To define a range of versions that a test can run with:
    #REQUIRE_VERSION=0.0
    #REQUIRE_VERSION_BELOW=99.9

  Configure environment variables to set the haproxy and varnishtest binaries to use
    setenv HAPROXY_PROGRAM /usr/local/sbin/haproxy
    setenv VARNISHTEST_PROGRAM /usr/local/bin/varnishtest
  or
    export HAPROXY_PROGRAM=/usr/local/sbin/haproxy
    export VARNISHTEST_PROGRAM=/usr/local/bin/varnishtest
EOF
  exit 0
}

add_range_to_test_list()
{
    level0="*.vtc"
    level1="h*.vtc"
    level2="s*.vtc"
    level3="l*.vtc"
    level4="b*.vtc"
    level5="k*.vtc"
    level6="e*.vtc"

    new_range=$(echo $1 | tr '-' ' ')
    non_digit=$(echo $new_range | grep '[^0-9 ]')
    if [ -n "$non_digit" ] ; then
        return
    fi
    if [ "$new_range" = "$1" ] ; then
        if [ $1 -gt 6 ] ; then
            return
        fi
        eval echo '$'level$1
        return
    fi
    if [ -z "$new_range" ] ; then
        return
    fi
    list=
    for l in $(seq $new_range) ; do
        if [ -n "l" ] ; then
            if [ -z "$list" ] ; then
                list="$(eval echo '$'level${l})"
            else
                list="$list $(eval echo '$'level${l})"
            fi
        fi
    done

    echo $list
}


build_test_list()
{
    # Remove any spacing character
    LEVEL="$(echo $LEVEL | tr -d ' ')"
    # Replave any comma character by a space character
    LEVEL="$(echo $LEVEL | tr ',' ' ')"
    list=
    for range in $LEVEL ; do
        if [ -z "$list" ] ; then
            list=$(add_range_to_test_list $range)
        else
            list="$list $(add_range_to_test_list $range)"
        fi
    done

    echo $list
}

build_find_expr()
{
    expr=
    for i in $@; do
        if [ -z "$expr" ] ; then
            expr="-name \"$i\""
        else
            expr="$expr -o -name \"$i\""
        fi
    done

    echo $expr
}

_startswith() {
  _str="$1"
  _sub="$2"
  echo "$_str" | grep "^$_sub" >/dev/null 2>&1
}

_findtests() {
  set -f
  LEVEL=${LEVEL:-0};
  list=$(build_test_list "$LEVEL")
  if [ -z "$list" ] ; then
      echo "Invalid level specification '"$LEVEL"' or no file was found."
      exit 1
  fi
  EXPR=$(build_find_expr $list)

  for i in $( find "$1" $(eval echo $EXPR) ); do
    skiptest=
    require_version="$(sed -ne 's/^#REQUIRE_VERSION=//p' "$i")"
    require_version_below="$(sed -ne 's/^#REQUIRE_VERSION_BELOW=//p' "$i")"
    require_options="$(sed -ne 's/^#REQUIRE_OPTIONS=//p' "$i" | sed  -e 's/,/ /g')"
    exclude_targets="$(sed -ne 's/^#EXCLUDE_TARGETS=//p' "$i" | sed  -e 's/,/ /g')"

    requiredoption="$(sed -ne 's/^#REQUIRE_OPTION=//p' "$i" | sed  -e 's/,.*//')"
    if [ -n "$requiredoption" ]; then
      require_options="$require_options $requiredoption"
    fi

    excludedtarget="$(sed -ne 's/^#EXCLUDE_TARGET=//p' "$i" | sed  -e 's/,.*//')"
    if [ -n "$excludedtarget" ]; then
      exclude_targets="$exclude_targets $excludedtarget"
    fi

    if [ -n "$require_version" ]; then
      if [ $(_version "$HAPROXY_VERSION") -lt $(_version "$require_version") ]; then
        echo "  Skip $i because option haproxy is version: $HAPROXY_VERSION"
        echo "    REASON: this test requires at least version: $require_version"
        skiptest=1
      fi
    fi
    if [ -n "$require_version_below" ]; then
      if [ $(_version "$HAPROXY_VERSION") -ge $(_version "$require_version_below") ]; then
        echo "  Skip $i because option haproxy is version: $HAPROXY_VERSION"
        echo "    REASON: this test requires a version below: $require_version_below"
        skiptest=1
      fi
    fi

    for excludedtarget in $exclude_targets; do
      if [ "$excludedtarget" = "$TARGET" ]; then
        echo "  Skip $i because haproxy is compiled for the excluded target $TARGET"
        skiptest=1
      fi
    done

    for requiredoption in $require_options; do
      alternatives=$(echo "$requiredoption" | sed -e 's/|/ /g')
      found=
      for alt in $alternatives; do
        if [ -n "$( echo "$OPTIONS" | grep "USE_$alt=1" )" ]; then
          found=1;
	fi
      done
      if [ -z $found ]; then
        echo "  Skip $i because haproxy is not compiled with the required option $requiredoption"
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
        --varnishtestparams)
          varnishtestparams="$2"
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
          keep_logs="-L"
          ;;
        --LEVEL)
          LEVEL="$2"
          shift
          ;;
        --use-htx)
          no_htx=""
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

_version() {
  echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\012", $1,$2,$3,$4); }';
}


HAPROXY_PROGRAM="${HAPROXY_PROGRAM:-${PWD}/haproxy}"
VARNISHTEST_PROGRAM="${VARNISHTEST_PROGRAM:-varnishtest}"
TESTDIR="${TMPDIR:-/tmp}"
REGTESTS=""

jobcount=""
verbose="-q"
debug=""
keep_logs="-l"
no_htx="#"
testlist=""

_process "$@";

echo ""
echo "########################## Preparing to run tests ##########################"

preparefailed=
if ! [ -x "$(command -v $HAPROXY_PROGRAM)" ]; then
  echo "haproxy not found in path, please specify HAPROXY_PROGRAM environment variable"
  preparefailed=1
fi
if ! [ -x "$(command -v $VARNISHTEST_PROGRAM)" ]; then
  echo "varnishtest not found in path, please specify VARNISHTEST_PROGRAM environment variable"
  preparefailed=1
fi
if [ $preparefailed ]; then
  exit 1
fi

{ read HAPROXY_VERSION; read TARGET; read OPTIONS; } << EOF
$($HAPROXY_PROGRAM -vv |grep 'HA-Proxy version\|TARGET\|OPTIONS' | sed 's/.* = //')
EOF

HAPROXY_VERSION=$(echo $HAPROXY_VERSION | cut -d " " -f 3)
echo "Testing with haproxy version: $HAPROXY_VERSION"

TESTRUNDATETIME="$(date '+%Y-%m-%d_%H-%M-%S')"

mkdir -p "$TESTDIR" || exit 1
TESTDIR=$(mktemp -d "$TESTDIR/haregtests-$TESTRUNDATETIME.XXXXXX") || exit 1

export TMPDIR="$TESTDIR"
export HAPROXY_PROGRAM="$HAPROXY_PROGRAM"

# Mimic implicit build options from haproxy MakeFile that are present for each target:

if [ $TARGET = generic ] ; then
  #generic system target has nothing specific
  OPTIONS="$OPTIONS USE_POLL=1 USE_TPROXY=1"
fi
if [ $TARGET = haiku ] ; then
  #For Haiku
  OPTIONS="$OPTIONS USE_POLL=1 USE_TPROXY=1"
fi
if [ $TARGET = linux22 ] ; then
  #This is for Linux 2.2
  OPTIONS="$OPTIONS USE_POLL=1 USE_TPROXY=1 USE_LIBCRYPT=1 USE_DL=1 USE_RT=1"
fi
if [ $TARGET = linux24 ] ; then
  #This is for standard Linux 2.4 with netfilter but without epoll()
  OPTIONS="$OPTIONS USE_NETFILTER=1 USE_POLL=1 USE_TPROXY=1 USE_CRYPT_H=1 USE_LIBCRYPT=1 USE_DL=1 USE_RT=1"
fi
if [ $TARGET = linux24e ] ; then
  #This is for enhanced Linux 2.4 with netfilter and epoll() patch>0.21
  OPTIONS="$OPTIONS USE_NETFILTER=1 USE_POLL=1 USE_EPOLL=1 USE_MY_EPOLL=1 USE_TPROXY=1 USE_CRYPT_H=1 USE_LIBCRYPT=1 USE_DL=1 USE_RT=1"
fi
if [ $TARGET = linux26 ] ; then
  #This is for standard Linux 2.6 with netfilter and standard epoll()
  OPTIONS="$OPTIONS USE_NETFILTER=1 USE_POLL=1 USE_EPOLL=1 USE_TPROXY=1 USE_CRYPT_H=1 USE_LIBCRYPT=1 USE_FUTEX=1 USE_DL=1 USE_RT=1"
fi
if [ $TARGET = linux2628 ] ; then
  #This is for standard Linux >= 2.6.28 with netfilter, epoll, tproxy and splice
  OPTIONS="$OPTIONS USE_NETFILTER=1 USE_POLL=1 USE_EPOLL=1 USE_TPROXY=1 USE_CRYPT_H=1 USE_LIBCRYPT=1 USE_LINUX_SPLICE=1 USE_LINUX_TPROXY=1 USE_ACCEPT4=1 USE_FUTEX=1 USE_CPU_AFFINITY=1 ASSUME_SPLICE_WORKS=1 USE_DL=1 USE_RT=1 USE_THREAD=1"
fi
if [ $TARGET = solaris ] ; then
  #This is for Solaris8
  OPTIONS="$OPTIONS USE_POLL=1 USE_TPROXY=1 USE_LIBCRYPT=1 USE_CRYPT_H=1 USE_GETADDRINFO=1 USE_THREAD=1"
fi
if [ $TARGET = freebsd ] ; then
  #This is for FreeBSD
  OPTIONS="$OPTIONS USE_POLL=1 USE_KQUEUE=1 USE_TPROXY=1 USE_LIBCRYPT=1 USE_THREAD=1 USE_CPU_AFFINITY=1"
fi
if [ $TARGET = osx ] ; then
  #This is for MacOS/X
  OPTIONS="$OPTIONS USE_POLL=1 USE_KQUEUE=1 USE_TPROXY=1"
fi
if [ $TARGET = openbsd ] ; then
  #This is for OpenBSD >= 5.7
  OPTIONS="$OPTIONS USE_POLL=1 USE_KQUEUE=1 USE_TPROXY=1 USE_ACCEPT4=1 USE_THREAD=1"
fi
if [ $TARGET = netbsd ] ; then
  #This is for NetBSD
  OPTIONS="$OPTIONS USE_POLL=1 USE_KQUEUE=1 USE_TPROXY=1"
fi
if [ $TARGET = aix51 ] ; then
  #This is for AIX 5.1
  OPTIONS="$OPTIONS USE_POLL=1 USE_LIBCRYPT=1"
fi
if [ $TARGET = aix52 ] ; then
  #This is for AIX 5.2 and later
  OPTIONS="$OPTIONS USE_POLL=1 USE_LIBCRYPT=1"
fi
if [ $TARGET = cygwin ] ; then
  #This is for Cygwin
  OPTIONS="$OPTIONS USE_POLL=1 USE_TPROXY=1"
fi

echo "Target : $TARGET"
echo "Options : $OPTIONS"

echo "########################## Gathering tests to run ##########################"
# if 'use-htx' option is set, but HAProxy version is lower to 1.9, disable it
if [ -z "$no_htx" ]; then
  if [ $(_version "$HAPROXY_VERSION") -lt $(_version "1.9") ]; then
    echo ""
    echo "WARNING : Unset HTX for haproxy (version: $HAPROXY_VERSION)"
    echo "    REASON: this test requires at least version: 1.9"
    echo ""
    no_htx="#"
  fi
fi

if [ -z "$REGTESTS" ]; then
  _findtests ./
else
  for t in $REGTESTS; do
    _findtests $t
  done
fi

echo "########################## Starting varnishtest ##########################"
echo "Testing with haproxy version: $HAPROXY_VERSION"
_vtresult=0
if [ -n "$testlist" ]; then
  if [ -n "$jobcount" ]; then
    jobcount="-j $jobcount"
  fi
  cmd="$VARNISHTEST_PROGRAM -k -t 10 -Dno-htx=${no_htx} $keep_logs $verbose $debug $jobcount $varnishtestparams $testlist"
  eval $cmd
  _vtresult=$?
else
  echo "No tests found that meet the required criteria"
fi


if [ $_vtresult -eq 0 ]; then
  # all tests were succesfull, removing tempdir (the last part.)
  # ignore errors is the directory is not empty or if it does not exist
   rmdir "$TESTDIR" 2>/dev/null
fi

if [ -d "${TESTDIR}" ]; then
  echo "########################## Gathering results ##########################"
  export TESTDIR
  find "$TESTDIR" -type d -name "vtc.*" -exec sh -c 'for i; do
    if [ ! -e "$i/LOG" ] ; then continue; fi

    cat <<- EOF | tee -a "$TESTDIR/failedtests.log"
$(echo "###### $(cat "$i/INFO") ######")
$(echo "## test results in: \"$i\"")
$(grep -E -- "^(----|\*    diag)" "$i/LOG")
EOF
  done' sh {} +
fi

exit $_vtresult
