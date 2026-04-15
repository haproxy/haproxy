#!/bin/sh -u
#
                __=	# echo
        SH_ARG_CFG=
        SH_ARG_DIR=
       SH_ARG_RATE="100.0 75.0 50.0 25.0 10.0 2.5 0.0 disabled off"
   SH_ARG_DURATION="300"
	   SH_NAME="$(basename "${0}")"
        SH_LOG_DIR="_logs"
SH_HAPROXY_PIDFILE="${SH_LOG_DIR}/haproxy.pid"
  SH_HTTPD_PIDFILE="${SH_LOG_DIR}/thttpd.pid"
      SH_USAGE_MSG="usage: ${SH_NAME} [-d duration] [-h] [-r rate-limits] cfg [dir]"


sh_exit ()
{
	sh_backup_clean "${SH_ARG_DIR}"

	test -z "${2:-}" && {
		echo
		echo "Script killed!"
	}

	test -n "${1:-}" && {
		echo
		echo "${1}"
		echo
	}

	${__} sh_httpd_stop
	rmdir -p "${SH_LOG_DIR}" 2>/dev/null
	exit ${2:-64}
}

sh_backup_make()
{
	_arg_dir="${1}"
	_var_file=

	for _var_file in haproxy.cfg otel.cfg otel.yml; do
		test -e "${_arg_dir}/${_var_file}.orig" || cp -af "${_arg_dir}/${_var_file}" "${_arg_dir}/${_var_file}.orig"
	done

	test "${_arg_dir}" = "fe" && sh_backup_make "be"
}

sh_backup_clean()
{
	_arg_dir="${1}"
	_var_file=

	for _var_file in haproxy.cfg otel.cfg otel.yml; do
		test -e "${_arg_dir}/${_var_file}.orig" && mv "${_arg_dir}/${_var_file}.orig" "${_arg_dir}/${_var_file}"
	done

	test "${_arg_dir}" = "fe" && sh_backup_clean "be"
}

sh_httpd_run ()
{

	test -e "${SH_HTTPD_PIDFILE}" && return

	thttpd -p 8000 -d . -nos -nov -l /dev/null -i "${SH_HTTPD_PIDFILE}"
}

sh_httpd_stop ()
{
	test -e "${SH_HTTPD_PIDFILE}" || return

	kill -TERM "$(cat ${SH_HTTPD_PIDFILE})"
	rm "${SH_HTTPD_PIDFILE}"
}

sh_haproxy_run ()
{
	_arg_cfg="${1}"
	_arg_dir="${2}"
	_arg_ratio="${3}"
	_var_sed_haproxy=
	_var_sed_otel=
	_var_sed_yml="s/\(exporters: *exporter_[a-z]*_\).*/\1dev_null/g"

	if test "${_arg_ratio}" = "disabled"; then
		_var_sed_otel="s/no \(option disabled\)/\1/"
	elif test "${_arg_ratio}" = "off"; then
		_var_sed_haproxy="s/^\(.* filter opentelemetry .*\)/#\1/g; s/^\(.* otel-group .*\)/#\1/g"
	else
		_var_sed_otel="s/\(rate-limit\) 100.0/\1 ${_arg_ratio}/"
	fi

	sed "${_var_sed_haproxy}" "${_arg_dir}/haproxy.cfg.orig" > "${_arg_dir}/haproxy.cfg"
	sed "${_var_sed_otel}"    "${_arg_dir}/otel.cfg.orig"    > "${_arg_dir}/otel.cfg"
	sed "${_var_sed_yml}"     "${_arg_dir}/otel.yml.orig"    > "${_arg_dir}/otel.yml"

	if test "${_arg_dir}" = "fe"; then
		sed "${_var_sed_yml}" "be/otel.yml.orig" > "be/otel.yml"

		if test "${_arg_ratio}" = "disabled" -o "${_arg_ratio}" = "off"; then
			sed "${_var_sed_haproxy}" "be/haproxy.cfg.orig" > "be/haproxy.cfg"
			sed "${_var_sed_otel}"    "be/otel.cfg.orig"    > "be/otel.cfg"
		fi
	fi

	./run-${_arg_cfg}.sh "" "${SH_HAPROXY_PIDFILE}" &
	sleep 5
}

sh_haproxy_stop ()
{
	# HAProxy does not create a pidfile if it is not running in daemon mode,
	# this is not used but is left regardless.
	#
	if test -e "${SH_HAPROXY_PIDFILE}"; then
		kill -TERM "$(cat ${SH_HAPROXY_PIDFILE})"
		rm "${SH_HAPROXY_PIDFILE}"
	fi

	pkill --signal SIGUSR1 haproxy
	wait
}

sh_wrk_run ()
{
	_arg_ratio="${1}"

	echo "--- rate-limit ${_arg_ratio} --------------------------------------------------"
	wrk -c8 -d${SH_ARG_DURATION} -t8 --latency http://localhost:10080/index.html
	echo "----------------------------------------------------------------------"
	echo

	sleep 10
}


while getopts d:hr: _var_getopt; do
	case "${_var_getopt}" in
	  d)	SH_ARG_DURATION="${OPTARG}" ;;
	  h)	sh_exit "${SH_USAGE_MSG}" 0 ;;
	  r)	SH_ARG_RATE="${OPTARG}" ;;
	  \?)	sh_exit "${SH_USAGE_MSG}" 64
	esac
done

shift $(expr ${OPTIND} - 1)
SH_ARG_CFG="${1:-}"
SH_ARG_DIR="${2:-${SH_ARG_CFG}}"


command -v thttpd >/dev/null 2>&1 || sh_exit "thttpd: command not found" 5
command -v wrk >/dev/null 2>&1    || sh_exit "wrk: command not found" 6

test -z "${SH_ARG_CFG}" -o -z "${SH_ARG_DIR}" && sh_exit "${SH_USAGE_MSG}" 64
mkdir -p "${SH_LOG_DIR}" || sh_exit "${SH_LOG_DIR}: Cannot create log directory" 1

if test "${SH_ARG_CFG}" = "all"; then
	_var_args="-r ${SH_ARG_RATE}"
	"${0}" "${_var_args}" sa sa
	"${0}" "${_var_args}" cmp cmp
	"${0}" "${_var_args}" ctx ctx
	"${0}" "${_var_args}" fe-be fe
	exit 0
elif test "${SH_ARG_CFG}" = "fe-be"; then
	SH_ARG_DIR="fe"
fi

test -f "run-${SH_ARG_CFG}.sh" || sh_exit "run-${SH_ARG_CFG}.sh: No such test script" 2
test -d "${SH_ARG_DIR}"        || sh_exit "${SH_ARG_DIR}: No such directory" 3

trap sh_exit INT TERM

echo "Running speed test ${SH_ARG_CFG}, start at $(date +"%F %T")"
exec 1>"${SH_LOG_DIR}/README-speed-${SH_ARG_CFG}"

${__} sh_backup_make "${SH_ARG_DIR}"
${__} sh_httpd_run
for _var_rate in ${SH_ARG_RATE}; do
	${__} sh_haproxy_run "${SH_ARG_CFG}" "${SH_ARG_DIR}" "${_var_rate}"
	${__} sh_wrk_run "${_var_rate}"
	${__} sh_haproxy_stop
done
sh_exit "" 0
