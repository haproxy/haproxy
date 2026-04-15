#!/bin/sh -u
#
# Copyright 2026 HAProxy Technologies, Miroslav Zagorac <mzagorac@haproxy.com>
#
SH_ARG_HAPROXY="${1:-$(realpath -L ${PWD}/../../../haproxy)}"
SH_ARG_PIDFILE="${2:-haproxy.pid}"
       SH_TIME="$(date +%s)"
    SH_LOG_DIR="_logs"
     SH_LOG_FE="${SH_LOG_DIR}/_log-$(basename "${0}" fe-be.sh)fe-${SH_TIME}"
     SH_LOG_BE="${SH_LOG_DIR}/_log-$(basename "${0}" fe-be.sh)be-${SH_TIME}"


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

test -x "${SH_ARG_HAPROXY}" || __exit "${SH_ARG_HAPROXY}: executable does not exist" 1
mkdir -p "${SH_LOG_DIR}"    || __exit "${SH_ARG_HAPROXY}: cannot create log directory" 2

echo "\n------------------------------------------------------------------------"
set -- -f haproxy-common.cfg -f be/haproxy.cfg -p "${SH_ARG_PIDFILE}"
echo "--- executing: ${SH_ARG_HAPROXY} ${@}" >${SH_LOG_BE}
"${SH_ARG_HAPROXY}" "${@}" >>"${SH_LOG_BE}" 2>&1 &

set -- -f haproxy-common.cfg -f fe/haproxy.cfg -p "${SH_ARG_PIDFILE}"
echo "--- executing: ${SH_ARG_HAPROXY} ${@}" >${SH_LOG_FE}
"${SH_ARG_HAPROXY}" "${@}" >>"${SH_LOG_FE}" 2>&1 &
echo "------------------------------------------------------------------------\n"

echo "Press CTRL-C to quit..."
wait
