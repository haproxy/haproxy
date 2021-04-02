#!/bin/sh
#
_ARG_DIR="${1:-.}"


get ()
{
	local _arg_tracer="${1}"
	local _arg_version="${2}"
	local _arg_url="${3}"
	local _arg_file="${4}"
	local _var_tmpfile="_tmpfile_"
	local _var_plugin="lib${_arg_tracer}_opentracing_plugin-${_arg_version}.so"

	test -e "${_var_plugin}" && return 0

	wget "https://github.com/${_arg_url}/releases/download/v${_arg_version}/${_arg_file}" -O "${_var_tmpfile}" || {
		rm "${_var_tmpfile}"
		return 1
	}

	case "$(file ${_var_tmpfile})" in
	  *shared\ object*)
		mv "${_var_tmpfile}" "${_var_plugin}" ;;

	  *gzip\ compressed\ data*)
		gzip -cd "${_var_tmpfile}" > "${_var_plugin}"
		rm "${_var_tmpfile}" ;;
	esac
}


mkdir -p "${_ARG_DIR}" && cd "${_ARG_DIR}" || exit 1

get dd 1.1.2 DataDog/dd-opentracing-cpp linux-amd64-libdd_opentracing_plugin.so.gz
get dd 1.2.0 DataDog/dd-opentracing-cpp linux-amd64-libdd_opentracing_plugin.so.gz

get jaeger 0.4.2 jaegertracing/jaeger-client-cpp libjaegertracing_plugin.linux_amd64.so
#et jaeger 0.5.0 jaegertracing/jaeger-client-cpp libjaegertracing_plugin.linux_amd64.so
#et jaeger 0.6.0 jaegertracing/jaeger-client-cpp libjaegertracing_plugin.linux_amd64.so

get lightstep 0.12.0 lightstep/lightstep-tracer-cpp linux-amd64-liblightstep_tracer_plugin.so.gz
get lightstep 0.13.0 lightstep/lightstep-tracer-cpp linux-amd64-liblightstep_tracer_plugin.so.gz

get zipkin 0.5.2 rnburn/zipkin-cpp-opentracing linux-amd64-libzipkin_opentracing_plugin.so.gz
