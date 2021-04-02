#!/bin/sh
#
_ARG_HAPROXY="${1:-$(realpath -L ${PWD}/../../../haproxy)}"
    _ARGS_FE="-f fe/haproxy.cfg"
    _ARGS_BE="-f be/haproxy.cfg"
       _TIME="$(date +%s)"
    _LOG_DIR="_logs"
     _LOG_FE="${_LOG_DIR}/_log-$(basename ${0} fe-be.sh)fe-${_TIME}"
     _LOG_BE="${_LOG_DIR}/_log-$(basename ${0} fe-be.sh)be-${_TIME}"


__exit ()
{
	test -z "${2}" && {
		echo
		echo "Script killed!"

		echo "Waiting for jobs to complete..."
		pkill --signal SIGUSR1 haproxy
		wait
	}

	test -n "${1}" && {
		echo
		echo "${1}"
		echo
	}

	exit ${2:-100}
}


trap __exit INT TERM

test -x "${_ARG_HAPROXY}" || __exit "${_ARG_HAPROXY}: executable does not exist" 1
mkdir -p "${_LOG_DIR}"    || __exit "${_ARG_HAPROXY}: cannot create log directory" 2

echo "\n------------------------------------------------------------------------"
echo "--- executing: ${_ARG_HAPROXY} ${_ARGS_BE} > ${_LOG_BE}"
"${_ARG_HAPROXY}" ${_ARGS_BE} >"${_LOG_BE}" 2>&1 &

echo "--- executing: ${_ARG_HAPROXY} ${_ARGS_FE} > ${_LOG_FE}"
"${_ARG_HAPROXY}" ${_ARGS_FE} >"${_LOG_FE}" 2>&1 &
echo "------------------------------------------------------------------------\n"

echo "Press CTRL-C to quit..."
wait
