#!/bin/sh -u
#
# Copyright 2026 HAProxy Technologies, Miroslav Zagorac <mzagorac@haproxy.com>
#
SH_ARG_HAPROXY="${1:-$(realpath -L ${PWD}/../../../haproxy)}"
SH_ARG_PIDFILE="${2:-haproxy.pid}"
       SH_ARGS="-f haproxy-common.cfg -f full/haproxy.cfg -p "${SH_ARG_PIDFILE}""
    SH_LOG_DIR="_logs"
        SH_LOG="${SH_LOG_DIR}/_log-$(basename "${0}" .sh)-$(date +%s)"


test -x "${SH_ARG_HAPROXY}" || exit 1
mkdir -p "${SH_LOG_DIR}"    || exit 2

echo "executing: ${SH_ARG_HAPROXY} ${SH_ARGS}" >${SH_LOG}
"${SH_ARG_HAPROXY}" ${SH_ARGS} >>"${SH_LOG}" 2>&1
