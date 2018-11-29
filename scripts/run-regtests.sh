#!/bin/sh

if [ "$1" = "--help" ]; then
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

    --varnishtestparams <ARGS>, passes custom ARGS to varnishtest
      run-regtests.sh --varnishtestparams "-n 10"

  Including text below into a .vtc file will check for its requirements
  related to haproxy's target and compilation options
    # Below targets are not capable of completing this test succesfully
    #EXCLUDE_TARGET=freebsd, abns sockets are not available on freebsd

    #EXCLUDE_TARGETS=dos,freebsd,windows

    # Below option is required to complete this test succesfully
    #REQUIRE_OPTION=OPENSSL, this test needs OPENSSL compiled in.

    #REQUIRE_OPTIONS=ZLIB,OPENSSL,LUA

    # To define a range of versions that a test can run with:
    #REQUIRE_VERSION=0.0
    #REQUIRE_VERSION_BELOW=99.9

  Configure environment variables to set the haproxy and varnishtest binaries to use
    setenv HAPROXY_PROGRAM /usr/local/sbin/haproxy
    setenv VARNISHTEST_PROGRAM /usr/local/bin/varnishtest
EOF
  return
fi

_startswith() {
  _str="$1"
  _sub="$2"
  echo "$_str" | grep "^$_sub" >/dev/null 2>&1
}

_findtests() {
  set -f
  LEVEL=${LEVEL:-0};
  EXPR='*.vtc'
  if [ $LEVEL = 1 ] ; then
    EXPR='h*.vtc';
  elif [ $LEVEL = 2 ] ; then
    EXPR='s*.vtc';
  elif [ $LEVEL = 3 ] ; then
    EXPR='l*.vtc';
  elif [ $LEVEL = 4 ] ; then
    EXPR='b*.vtc';
  fi

  for i in $( find "$1" -name "$EXPR" ); do
    skiptest=
    require_version="$(grep "#REQUIRE_VERSION=" "$i" | sed -e 's/.*=//')"
    require_version_below="$(grep "#REQUIRE_VERSION_BELOW=" "$i" | sed -e 's/.*=//')"
    require_options="$(grep "#REQUIRE_OPTIONS=" "$i" | sed -e 's/.*=//')"
    exclude_targets=",$(grep "#EXCLUDE_TARGETS=" "$i" | sed -e 's/.*=//'),"

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

    if [ -n "$( echo "$exclude_targets" | grep ",$TARGET," )" ]; then
      echo "  Skip $i because exclude_targets"
      echo "    REASON: exclude_targets '$exclude_targets' contains '$TARGET'"
      skiptest=1
    fi

    #echo "REQUIRE_OPTIONS : $require_options"
    for requiredoption in $(echo $require_options | tr "," "\012" ); do
      if [ -z "$( echo "$OPTIONS" | grep "USE_$requiredoption=1" )" ]
      then
        echo "  Skip $i because option $requiredoption not found"
        echo -n "    REASON: "
        echo -n "$required" | sed -e 's/.*,//' -e 's/^[[:space:]]//'
        echo
        skiptest=1
      fi
    done
    for required in "$(grep "#REQUIRE_OPTION=" "$i")";
    do
      if [ -z "$required" ]
      then
        continue
      fi
      requiredoption=$(echo "$required" | sed -e 's/.*=//' -e 's/,.*//')
      if [ -z "$( echo "$OPTIONS" | grep "USE_$requiredoption=1" )" ]
      then
        echo "  Skip $i because option $requiredoption not found"
        echo -n "    REASON: "
        echo "$required" | sed -e 's/.*,//' -e 's/^[[:space:]]//'
        skiptest=1
      fi
    done
    testtarget=$(grep "#EXCLUDE_TARGET=" "$i")
    if [ "$( echo "$testtarget" | grep "#EXCLUDE_TARGET=$TARGET," )" ]
    then
      echo "  Skip $i because: TARGET = $TARGET"
      echo -n "    REASON: "
      echo "$testtarget" | sed -e 's/.*,//' -e 's/^[[:space:]]//'
      skiptest=1
    fi

    if [ -z $skiptest ]; then
      echo "  Add test: $i"
      testlist="$testlist $i"
    fi
  done
}

_process() {
  jobcount=""
  verbose="-q"

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
        --LEVEL)
          LEVEL="$2"
          shift
          ;;
        *)
          echo "Unknown parameter : $1"
          return 1
          ;;
      esac
    else
      _findtests "$1"
      pathwasset=1
    fi
    shift 1
  done
  if [ -z $pathwasset ]; then
    # no path was given, find all tests under current path
    _findtests ./
  fi
}

_version() {
  echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\012", $1,$2,$3,$4); }';
}

echo ""
echo "########################## Preparing to run tests ##########################"

HAPROXY_PROGRAM="${HAPROXY_PROGRAM:-${PWD}/haproxy}"
VARNISHTEST_PROGRAM="${VARNISHTEST_PROGRAM:-varnishtest}"

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

TESTDIR="${TMPDIR:-/tmp}"
mkdir -p "$TESTDIR" || exit 1
TESTDIR=$(mktemp -d "$TESTDIR/$TESTRUNDATETIME.XXXXXX") || exit 1

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

testlist=""
pathwasset=

_process "$@";

echo "########################## Starting varnishtest ##########################"
echo "Testing with haproxy version: $HAPROXY_VERSION"
_vtresult=0
if [ -n "$testlist" ]; then
  if [ -n "$jobcount" ]; then
    jobcount="-j $jobcount"
  fi
  $VARNISHTEST_PROGRAM $varnishtestparams $verbose $jobcount -l -k -t 10 $testlist
  _vtresult=$?
else
  echo "No tests found that meet the required criteria"
fi
if [ $_vtresult != 0 ]
then
  echo "########################## Gathering failed results ##########################"
  export TESTDIR
  find "$TESTDIR" -type d -name "vtc.*" -exec sh -c 'for i; do
    if [ ! -e "$i/LOG" ] ; then continue; fi
    cat <<- EOF | tee -a "$TESTDIR/failedtests.log"
$(echo "###### $(cat "$i/INFO") ######")
$(echo "## test results in: \"$i\"")
$(grep -- ---- "$i/LOG")
EOF
  done' sh {} +
  exit 1
else
  # all tests were succesfull, removing tempdir (the last part.)
  rmdir "$TESTDIR"
fi
exit 0
