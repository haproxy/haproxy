#!/usr/bin/env bash

# Usage: mkhdr -l <len> -t <type> -f <flags> -sid <sid> > hdr.bin
# All fields are optional. 0 assumed when absent.

USAGE=\
"Usage: %s [-l <len>] [-t <type>] [-f <flags>] [-i <sid>] > hdr.bin
        Numbers are decimal or 0xhex. Not set=0.

Supported symbolic types (case insensitive prefix match):
   DATA        (0x00)      PUSH_PROMISE   (0x05)
   HEADERS     (0x01)      PING           (0x06)
   PRIORITY    (0x02)      GOAWAY         (0x07)
   RST_STREAM  (0x03)      WINDOW_UPDATE  (0x08)
   SETTINGS    (0x04)      CONTINUATION   (0x09)

Supported symbolic flags (case insensitive prefix match):
   ES          (0x01)      PAD            (0x08)
   EH          (0x04)      PRIO           (0x20)

"

LEN=
TYPE=
FLAGS=
ID=

die() {
	[ "$#" -eq 0 ] || echo "$*" >&2
	exit 1
}

quit() {
	[ "$#" -eq 0 ] || echo "$*"
	exit 0
}

# print usage with $1 as the cmd name
usage() {
	printf "$USAGE" "$1";
}

# Send frame made of $1 $2 $3 $4 to stdout.
# Usage: mkframe <len> <type> <flags> <id>
mkframe() {
	local L="${1:-0}"
	local T="${2:-0}"
	local F="${3:-0}"
	local I="${4:-0}"
	local t f

	# get the first match in this order
	for t in DATA:0x00 HEADERS:0x01 RST_STREAM:0x03 SETTINGS:0x04 PING:0x06 \
		 GOAWAY:0x07 WINDOW_UPDATE:0x08 CONTINUATION:0x09 PRIORITY:0x02 \
		 PUSH_PROMISE:0x05; do
		if [ -z "${t##${T^^*}*}" ]; then
			T="${t##*:}"
			break
		fi
	done

	if [ -n "${T##[0-9]*}" ]; then
		echo "Unknown type '$T'" >&2
		usage "${0##*}"
		die
	fi

	# get the first match in this order
	for f in ES:0x01 EH:0x04 PAD:0x08 PRIO:0x20; do
		if [ -z "${f##${F^^*}*}" ]; then
			F="${f##*:}"
		fi
	done

	if [ -n "${F##[0-9]*}" ]; then
		echo "Unknown type '$T'" >&2
		usage "${0##*}"
		die
	fi

	L=$(( L )); T=$(( T )); F=$(( F )); I=$(( I ))

	L0=$(( (L >> 16) & 255 )); L0=$(printf "%02x" $L0)
	L1=$(( (L >>  8) & 255 )); L1=$(printf "%02x" $L1)
	L2=$(( (L >>  0) & 255 )); L2=$(printf "%02x" $L2)

	T0=$(( (T >>  0) & 255 )); T0=$(printf "%02x" $T0)
	F0=$(( (F >>  0) & 255 )); F0=$(printf "%02x" $F0)

	I0=$(( (I >> 24) & 127 )); I0=$(printf "%02x" $I0)
	I1=$(( (I >> 16) & 255 )); I1=$(printf "%02x" $I1)
	I2=$(( (I >>  8) & 255 )); I2=$(printf "%02x" $I2)
	I3=$(( (I >>  0) & 255 )); I3=$(printf "%02x" $I3)

	printf "\x$L0\x$L1\x$L2\x$T0\x$F0\x$I0\x$I1\x$I2\x$I3"
}

## main

if [ $# -le 1 ]; then
	usage "${0##*}"
	die
fi

while [ -n "$1" -a -z "${1##-*}" ]; do
	case "$1" in
		-l)        LEN="$2"      ; shift 2 ;;
		-t)        TYPE="$2"     ; shift 2 ;;
		-f)        FLAGS="$2"    ; shift 2 ;;
		-i)        ID="$2"       ; shift 2 ;;
		-h|--help) usage "${0##*}"; quit;;
		*)         usage "${0##*}"; die ;;
	esac
done

if [ $# -gt 0 ]; then
	usage "${0##*}"
	die
fi

# default values for LEN and ID
LEN=${LEN:-0};
if [ -n "${LEN##[0-9]*}" ]; then
	echo "Unparsable length '$LEN'" >&2
	usage "${0##*}"
	die
fi

ID=${ID:-0};
if [ -n "${ID##[0-9]*}" ]; then
	echo "Unparsable stream ID '$ID'" >&2
	usage "${0##*}"
	die
fi

mkframe "$LEN" "$TYPE" "$FLAGS" "$ID"

exit 0
