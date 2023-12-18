#!/bin/bash

# note: the program may re-execute itself: when it has more than one patch to
# process, it will call itself with one patch only in argument. When called
# with a single patch in argument, it will always start the analysis directly.

# The program uses several environment variables:
# - EXT         file name extension for the response
# - MODEL       path to the model file (GGUF format)
# - FORCE       force to re-process existing patches
# - PROGRAM     path to the script to be called
# - CACHE       path to the prompt cache (optional)
# - CACHE_RO    force cache to remain read-only
# - PROMPT_PFX  path to the prompt prefix (before the patch)
# - PROMPT_SFX  path to the prompt suffix (after the patch)
# - TOT_CPUS    total number of usable CPUs (def: nproc or 1)
# - SLOT_CPUS   if defined, it's an array of CPU sets for each running slot
# - CPU_SLOT    passed by the first level to the second one to allow binding
#               to a specific CPU set based on the slot number from 0 to N-1.

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

# detect if running under -x, pass it down to sub-processes
#opt=; set -o | grep xtrace | grep -q on && opt=-x

USAGE="Usage: ${0##*/} [ -s slots ] patch..."
MYSELF="$0"
TOT_CPUS=${TOT_CPUS:-$(nproc)}
TOT_CPUS=${TOT_CPUS:-1}
SLOTS=1


while [ -n "$1" -a -z "${1##-*}" ]; do
	case "$1" in
		-s)        SLOTS="$2"    ; shift 2 ;;
		-h|--help) quit "$USAGE" ;;
		*)         die  "$USAGE" ;;
	esac
done

[ -n "$EXT" ]        || die "Missing extension name (EXT)"
[ -n "$MODEL" ]      || die "Missing model name (MODEL)"
[ -n "$PROGRAM" ]    || die "Missing program name (PROGRAM)"
[ -n "$PROMPT_PFX" ] || die "Missing prompt prefix (PROMPT_PFX)"
[ -n "$PROMPT_SFX" ] || die "Missing prompt suffix (PROMPT_SFX)"

PATCHES=( "$@" )

if [ ${#PATCHES[@]} = 0 ]; then
        die "$USAGE"
elif [ ${#PATCHES[@]} = 1 ]; then
        # really execute
        taskset_cmd=""
        if [ -n "$CPU_SLOT" ] && [ -n "${SLOT_CPUS[$CPU_SLOT]}" ]; then
                taskset_cmd="taskset -c ${SLOT_CPUS[$CPU_SLOT]}"
        fi
        export CPU=$TOT_CPUS
        ${taskset_cmd} ${PROGRAM} "${PATCHES[0]}"
else
        # divide CPUs by number of slots
        export TOT_CPUS=$(( (TOT_CPUS + SLOTS - 1) / SLOTS ))
        # reexecute ourselves in parallel with a single patch each
        xargs -n 1 -P "${SLOTS}" --process-slot-var=CPU_SLOT "${MYSELF}" -s 1 <<< "${PATCHES[@]}"
fi

