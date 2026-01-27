#!/bin/sh -u
#
# Copyright 2026 HAProxy Technologies, Miroslav Zagorac <mzagorac@haproxy.com>
#
SH_FILE="${1:-}"
 SH_EXT="${2:-}"


if test ${#} -ne 2; then
	echo
	echo "usage: $(basename "${0}") input-file test-name"
	echo
	exit 64
fi

sed '
	s/^\( *\)\(filename:\)\( *\)_\(_[a-z]*\)/\1\2\3__'"${SH_EXT}"'\4/g
	s/^\( *\)\(file_pattern:\)\( *\)"_\(_[a-z]*_[^"]*\)"/\1\2\3"__'"${SH_EXT}"'\4"/g
	s/^\( *\)\(- service.instance.id:\)\( *\).*/\1\2\3"id-'"${SH_EXT}"'"/g
	s/^\( *\)\(- service.name:\)\( *\).*/\1\2\3"'"${SH_EXT}"'"/g
	s/^\( *\)\(- service.namespace:\)\( *\)\("otelc\)/\1\2\3"HAProxy/g
	s/^\( *\)\(scope_name:\)\( *\)"OTEL C wrapper /\1\2 "HAProxy OTEL /g
	s/^\( *\)\(exporters:\)\( *\)\(exporter_[a-z]*_\).*/\1\2\3\4otlp_http/g
' "${SH_FILE}"
