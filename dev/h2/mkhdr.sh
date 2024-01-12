#!/usr/bin/env bash

# Usage: mkhdr -l <len> -t <type> -f <flags> -sid <sid> > hdr.bin
# All fields are optional. 0 assumed when absent.

USAGE=\
"Usage: %s [-l <len> ] [-t <type>] [-f <flags>[,...]] [-i <sid>] [ -d <data> ]
           [ -e <name> <value> ]* [ -r|-R raw ] [ -h | --help ] > hdr.bin
        Numbers are decimal or 0xhex. Not set=0. If <data> is passed, it points
        to a file that is read and chunked into frames of <len> bytes. -e
        encodes a headers frame (by default) with all headers at once encoded
        in literal. Use type 'p' for the preface. Use -r to pass raw data or
        -R to pass raw hex codes (hex digit pairs, blanks ignored).

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
RAW=
HDR=( )

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
	local t f f2 f3

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

	# get the first match in this order, for each entry delimited by ','.
	# E.g.: "-f ES,EH"
	f2=${F^^*}; F=0

	while [ -n "$f2" ]; do
		f3="${f2%%,*}"
		tmp=""
		for f in ES:0x01 EH:0x04 PAD:0x08 PRIO:0x20; do
			if [ -n "$f3" -a -z "${f##${f3}*}" ]; then
				tmp="${f#*:}"
				break
			fi
		done

		if [ -n "$tmp" ]; then
			F=$(( F | tmp ))
			f2="${f2#$f3}"
			f2="${f2#,}"
		elif [ -z "${f3##[X0-9A-F]*}" ]; then
			F=$(( F | f3 ))
			f2="${f2#$f3}"
			f2="${f2#,}"
		else
			echo "Unknown flag(s) '$f3'" >&2
			usage "${0##*}"
			die
		fi
	done

	if [ -n "$f2" ]; then
		F="${f2} | ${F}"
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
		-d)        DATA="$2"     ; shift 2 ;;
		-r)        RAW="$2"      ; shift 2 ;;
		-R)        RAW="$(printf $(echo -n "${2// /}" | sed -e 's/\([^ ][^ ]\)/\\\\x\1/g'))" ; shift 2 ;;
                -e)        TYPE=1; HDR[${#HDR[@]}]="$2=$3"; shift 3 ;;
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

if [ "$TYPE" = "p" ]; then
        printf "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
elif [ -z "$DATA" ]; then
        # If we're trying to emit literal headers, let's pre-build the raw data
        # and measure their total length.
        if [ ${#HDR[@]} -gt 0 ]; then
                # limited to 127 bytes for name and value
                for h in "${HDR[@]}"; do
                        n=${h%%=*}
                        v=${h#*=}
                        nl=${#n}
                        vl=${#v}
	                nl7=$(printf "%02x" $((nl & 127)))
	                vl7=$(printf "%02x" $((vl & 127)))
	                RAW="${RAW}\x40\x${nl7}${n}\x${vl7}${v}"
                done
        fi

        # compute length if RAW set
        if [ -n "$RAW" ]; then
                LEN=$(printf "${RAW}" | wc -c)
        fi

	mkframe "$LEN" "$TYPE" "$FLAGS" "$ID"

        # now emit the literal data of advertised length
        if [ -n "$RAW" ]; then
                printf "${RAW}"
        fi
else
	# read file $DATA in <LEN> chunks and send it in multiple frames
	# advertising their respective lengths.
	[ $LEN -gt 0 ] || LEN=16384

	while read -rN "$LEN" payload || [ ${#payload} -gt 0 ]; do
		mkframe "${#payload}" "$TYPE" "$FLAGS" "$ID"
		echo -n "$payload"
	done < "$DATA"
fi

exit 0
