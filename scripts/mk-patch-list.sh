#!/bin/bash

die() {
	[ "$#" -eq 0 ] || echo "$*" >&2
	exit 1
}

err() {
	echo "$*" >&2
}

quit() {
	[ "$#" -eq 0 ] || echo "$*"
	exit 0
}

#### Main

USAGE="Usage: ${0##*/} [-o <output_dir>] [-s <start_num>] [-b <base>] commit_id..."
OUTPUT=
BASE=
NUM=

while [ -n "$1" -a -z "${1##-*}" ]; do
	case "$1" in
		-b)        BASE="$2"      ; shift 2 ;;
		-o)        OUTPUT="$2"    ; shift 2 ;;
		-s)        NUM="$2"       ; shift 2 ;;
		-h|--help) quit "$USAGE" ;;
		*)         die  "$USAGE" ;;
	esac
done

PATCHES=( "$@" )
NUM=${NUM:-1}

for p in ${PATCHES[@]}; do
        if [ -n "$BASE" ]; then
                # find the patch number from the base.
                # E.g. v2.9-dev0-774-gd710dfbac
                NUM=$(git describe --match "$BASE" "$p")
                NUM=${NUM#"$BASE"-}
                NUM=${NUM%-*}
        fi
        git format-patch -k -1 --start-number=$NUM ${OUTPUT:+-o $OUTPUT} "$p"
        ((NUM++))
done
