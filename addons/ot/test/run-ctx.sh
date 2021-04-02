#!/bin/sh
#
_ARG_HAPROXY="${1:-$(realpath -L ${PWD}/../../../haproxy)}"
       _ARGS="-f ctx/haproxy.cfg"
    _LOG_DIR="_logs"
        _LOG="${_LOG_DIR}/_log-$(basename ${0} .sh)-$(date +%s)"


test -x "${_ARG_HAPROXY}" || exit 1
mkdir -p "${_LOG_DIR}"    || exit 2

echo "executing: ${_ARG_HAPROXY} ${_ARGS} > ${_LOG}"
"${_ARG_HAPROXY}" ${_ARGS} >"${_LOG}" 2>&1
