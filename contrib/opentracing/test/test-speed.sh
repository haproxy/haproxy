#!/bin/sh
#
      _ARG_CFG="${1}"
      _ARG_DIR="${2}"
      _LOG_DIR="_logs"
_HTTPD_PIDFILE="${_LOG_DIR}/thttpd.pid"


httpd_run ()
{

	test -e "${_HTTPD_PIDFILE}" && return

	thttpd -p 8000 -d . -nos -nov -l /dev/null -i "${_HTTPD_PIDFILE}"
}

httpd_stop ()
{
	test -e "${_HTTPD_PIDFILE}" || return

	kill -TERM "$(cat ${_HTTPD_PIDFILE})"
	rm "${_HTTPD_PIDFILE}"
}

haproxy_run ()
{
	_arg_ratio="${1}"
	_var_sed_ot=
	_var_sed_haproxy=

	if test "${_arg_ratio}" = "disabled"; then
		_var_sed_ot="s/no \(option disabled\)/\1/"
	elif test "${_arg_ratio}" = "off"; then
		_var_sed_haproxy="s/^\(.* filter opentracing .*\)/#\1/g; s/^\(.* ot-group .*\)/#\1/g"
	else
		_var_sed_ot="s/\(rate-limit\) 100.0/\1 ${_arg_ratio}/"
	fi

	sed "${_var_sed_haproxy}" "${_ARG_DIR}/haproxy.cfg.in" > "${_ARG_DIR}/haproxy.cfg"
	sed "${_var_sed_ot}"      "${_ARG_DIR}/ot.cfg.in" > "${_ARG_DIR}/ot.cfg"

	if test "${_ARG_DIR}" = "fe"; then
		if test "${_arg_ratio}" = "disabled" -o "${_arg_ratio}" = "off"; then
			sed "${_var_sed_haproxy}" "be/haproxy.cfg.in" > "be/haproxy.cfg"
			sed "${_var_sed_ot}"      "be/ot.cfg.in" > "be/ot.cfg"
		fi
	fi

	./run-${_ARG_CFG}.sh &
	sleep 5
}

wrk_run ()
{
	_arg_ratio="${1}"

	echo "--- rate-limit ${_arg_ratio} --------------------------------------------------"
	wrk -c8 -d300 -t8 --latency http://localhost:10080/index.html
	echo "----------------------------------------------------------------------"
	echo

	sleep 10
}


mkdir -p "${_LOG_DIR}" || exit 1

if test "${_ARG_CFG}" = "all"; then
	${0} fe-be fe > "${_LOG_DIR}/README-speed-fe-be"
	${0} sa sa    > "${_LOG_DIR}/README-speed-sa"
	${0} cmp cmp  > "${_LOG_DIR}/README-speed-cmp"
	${0} ctx ctx  > "${_LOG_DIR}/README-speed-ctx"
	exit 0
fi

test -n "${_ARG_CFG}" -a -f "run-${_ARG_CFG}.sh" || exit 2
test -n "${_ARG_DIR}" -a -d "${_ARG_DIR}"        || exit 3

test -e "${_ARG_DIR}/haproxy.cfg.in" || cp -af "${_ARG_DIR}/haproxy.cfg" "${_ARG_DIR}/haproxy.cfg.in"
test -e "${_ARG_DIR}/ot.cfg.in"      || cp -af "${_ARG_DIR}/ot.cfg" "${_ARG_DIR}/ot.cfg.in"
if test "${_ARG_DIR}" = "fe"; then
	test -e "be/haproxy.cfg.in" || cp -af "be/haproxy.cfg" "be/haproxy.cfg.in"
	test -e "be/ot.cfg.in"      || cp -af "be/ot.cfg" "be/ot.cfg.in"
fi

httpd_run

for _var_ratio in 100.0 50.0 10.0 2.5 0.0 disabled off; do
	haproxy_run "${_var_ratio}"
	wrk_run "${_var_ratio}"

	pkill --signal SIGUSR1 haproxy
	wait
done

httpd_stop
