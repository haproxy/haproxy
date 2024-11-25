#!/usr/bin/env bash

# This script is used to resolve various flags that appear on "show sess all".
# All identified ones will be appended at the end, with a short name and their
# value, followed by either the value resolved by "flags" when it's found, or
# by the copy-pastable command to use to resolve them. The path to FLAGS is
# searched in this order: 1) $FLAGS, 2) in the path, 3) dev/flags/flags, 4)
# in the same directory as the script.
#
# This script is horrendous, but it's not a reason for making it even more
# disgusting. The big regex flag mapping mess at the end is readable on a
# large screen and it's easier to spot mistakes using this aligned format,
# so please preserve this as much as possible and avoid multi-line formats.
#
# The append_* functions provide different variants that are still commented
# out. It's mostly a matter of taste, they're equivalent.
#
# Usage: socat /path/to/socket - <<< "show sess all" | ./$0 > output
#
# options:
#    --color=never, --no-color: never colorize output
#    --color=always: always colorize output (default: only on terminal)

# look for "flags in path then in dev/flags/flags then next to the script"
FLAGS="${FLAGS:-$(command -v flags)}"
if [ -z "$FLAGS" ]; then
        if [ -e dev/flags/flags ]; then
                FLAGS=dev/flags/flags;
        elif [ -e "${0%/*}/flags" ]; then
                FLAGS="${0%/*}/flags"
        else
                # OK still not found,let's write a copy-pastable command
                FLAGS="echo ./flags"
        fi
fi

HTTP_METH=( "OPTIONS" "GET" "HEAD" "POST" "PUT" "DELETE" "TRACE" "CONNECT" "OTHER" )
out=( )
decode=( )

# returns str $2 and $3 concatenated with enough spaces in between so that the
# total size doesn't exceed $1 chars, but always inserts at least one space.
justify() {
        local pad=" "
        local str

        while str="${2}${pad}${3}" && [ ${#str} -le $1 ]; do
                pad="${pad} "
        done
        echo -n "$str"
}

# remove spaces at the beginning and end in "$1"
trim() {
        while [ -n "$1" -a -z "${1## *}" ]; do
                set -- "${1# }"
        done
        while [ -n "$1" -a -z "${1%%* }" ]; do
                set -- "${1% }"
        done
        echo -n "$1"
}

# pass $1=ctx name, $2=argname, $3=value, append the decoded line to decode[]
append_flag() {
        set -- "$1" "$2" "$(printf "%#x" $3)"
        #decode[${#decode[@]}]="$1=$3 [ $(set -- $($FLAGS $2 $3 | cut -f2- -d=); echo $*) ]"
        #decode[${#decode[@]}]="$(printf "%-14s %10s  %s" $1 $3 "$(set -- $($FLAGS $2 $3 | cut -f2- -d=); echo $*)")"
        #decode[${#decode[@]}]="$(justify 22 "$1" "$3")  $(set -- $($FLAGS $2 $3 | cut -f2- -d=); echo $*)"
        decode[${#decode[@]}]="$(justify 22 "$1" "$3")  $(set -- $($FLAGS $2 $3 | cut -f2- -d= | tr -d '|'); echo "$*")"
        #decode[${#decode[@]}]="$(justify 22 "$1" "$3")  $(set -- $($FLAGS $2 $(printf "%#x" $3) | cut -f2- -d= | tr -d '|'); echo "$*")"
        #decode[${#decode[@]}]="$(justify 22 "$1" "$3")  $(trim "$($FLAGS $2 $3 | cut -f2- -d= | tr -d '|')")"
        #decode[${#decode[@]}]="$(justify 22 "$1" "$3")  $(trim "$($FLAGS $2 $3 | cut -f2- -d= | tr -d ' ')")"
}

# pass $1=ctx name, $2=value, $3=decoded value
append_str() {
        #decode[${#decode[@]}]="$1=$2 [ $3 ]"
        #decode[${#decode[@]}]="$(printf "%-14s %10s  %s" $1 $2 $3)"
        decode[${#decode[@]}]="$(justify 22 "$1" "$2")  $(trim $3)"
}

# dump and reset the buffers
dump_and_reset() {
        local line

        line=0
        while [ $line -lt ${#out[@]} ]; do
                if [ -n "$COLOR" ]; then
                        # highlight name=value for values made of upper case letters
                        echo "${out[$line]}" | \
                                sed -e 's,\(^0x.*\),\x1b[1;37m\1\x1b[0m,g' \
                                    -e 's,\([^ ,=]*\)=\([A-Z][^:, ]*\),\x1b[1;36m\1\x1b[0m=\x1b[1;33m\2\x1b[0m,g'

                else
                        echo "${out[$line]}"
                fi
                ((line++))
        done

        [ ${#decode[@]} -eq 0 ] || echo "  -----------------------------------"

        line=0
        while [ $line -lt ${#decode[@]} ]; do
                echo "  ${decode[$line]}"
                ((line++, total++))
        done

        [ ${#decode[@]} -eq 0 ] || echo "  -----------------------------------"

        decode=( )
        out=( )
}

### main entry point

if [ -t 1 ]; then
        # terminal on stdout, enable color by default
        COLOR=1
else
        COLOR=
fi

if [ "$1" == "--no-color" -o "$1" == "--color=never" ]; then
        shift
        COLOR=
elif [ "$1" == "--color=always" ]; then
        shift
        COLOR=1
fi

ctx=strm
while read -r; do
        [ "$REPLY" != "EOF" ] || break  # for debugging

        if [[ "$REPLY" =~ ^[[:blank:]]*task= ]]; then
                ctx=task;
        elif [[ "$REPLY" =~ ^[[:blank:]]*txn= ]]; then
                ctx=txn;
        elif [[ "$REPLY" =~ ^[[:blank:]]*scf= ]]; then
                ctx=scf;
        elif [[ "$REPLY" =~ ^[[:blank:]]*co0= ]]; then
                ctx=cof;
        elif [[ "$REPLY" =~ ^[[:blank:]]*app0= ]]; then
                ctx=appf;
        elif [[ "$REPLY" =~ ^[[:blank:]]*req= ]]; then
                ctx=req;
        elif [[ "$REPLY" =~ ^[[:blank:]]*scb= ]]; then
                ctx=scb;
        elif [[ "$REPLY" =~ ^[[:blank:]]*co1= ]]; then
                ctx=cob;
        elif [[ "$REPLY" =~ ^[[:blank:]]*app1= ]]; then
                ctx=appb;
        elif [[ "$REPLY" =~ ^[[:blank:]]*res= ]]; then
                ctx=res;
        elif [[ "$REPLY" =~ ^0x ]]; then
                # here we dump what we have and we reset
                dump_and_reset
                ctx=strm;
        fi

        if [ $ctx = strm ]; then
                ! [[ "$REPLY" =~ [[:blank:]]flags=([0-9a-fx]*) ]]      || append_flag strm.flg    strm "${BASH_REMATCH[1]}"
        elif [ $ctx = task ]; then
                ! [[ "$REPLY" =~ \(state=([0-9a-fx]*) ]]               || append_flag task.state  task "${BASH_REMATCH[1]}"
        elif [ $ctx = txn ]; then
                ! [[ "$REPLY" =~ [[:blank:]]meth=([^[:blank:]]*) ]]       || append_str txn.meth "${BASH_REMATCH[1]}" "${HTTP_METH[$((${BASH_REMATCH[1]}))]}"
                ! [[ "$REPLY" =~ [[:blank:]]flags=([0-9a-fx]*) ]]      || append_flag txn.flg     txn  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]req\.f=([0-9a-fx]*) ]]     || append_flag txn.req.flg hmsg "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]rsp\.f=([0-9a-fx]*) ]]     || append_flag txn.rsp.flg hmsg "${BASH_REMATCH[1]}"
        elif [ $ctx = scf ]; then
                ! [[ "$REPLY" =~ [[:blank:]]flags=([0-9a-fx]*) ]]      || append_flag f.sc.flg    sc   "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]endp=[[:alnum:]]*,[[:alnum:]]*,([0-9a-fx]*) ]] || append_flag f.sc.sd.flg sd "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]h1s.*\.sd\.flg=([0-9a-fx]*) ]] || append_flag f.h1s.sd.flg sd "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]h1s\.flg=([0-9a-fx]*) ]]   || append_flag f.h1s.flg   h1s  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]h1c\.flg=([0-9a-fx]*) ]]   || append_flag f.h1c.flg   h1c  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ ^[[:blank:]]*\.sc=.*\.flg=.*\.app=.*\.sd=[^=]*\.flg=([0-9a-fx]*) ]] || append_flag f.h2s.sd.flg sd "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]h2s.*\.flg=([0-9a-fx]*) ]] || append_flag f.h2s.flg   h2s  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]h2c.*\.flg=([0-9a-fx]*) ]] || append_flag f.h2c.flg   h2c  "${BASH_REMATCH[1]}"
        elif [ $ctx = cof ]; then
                ! [[ "$REPLY" =~ [[:blank:]]flags=([0-9a-fx]*) ]]      || append_flag f.co.flg    conn "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]fd.state=([0-9a-fx]*) ]]   || append_flag f.co.fd.st  fd   0x"${BASH_REMATCH[1]#0x}"
        elif [ $ctx = req ]; then
                ! [[ "$REPLY" =~ [[:blank:]]\(f=([0-9a-fx]*) ]]        || append_flag req.flg     chn  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]an=([0-9a-fx]*) ]]         || append_flag req.ana     ana  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]htx.*flags=([0-9a-fx]*) ]] || append_flag req.htx.flg htx  "${BASH_REMATCH[1]}"
        elif [ $ctx = scb ]; then
                ! [[ "$REPLY" =~ [[:blank:]]flags=([0-9a-fx]*) ]]      || append_flag b.sc.flg    sc   "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]endp=[[:alnum:]]*,[[:alnum:]]*,([0-9a-fx]*) ]] || append_flag b.sc.sd.flg sd "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]h1s.*\.sd\.flg=([0-9a-fx]*) ]] || append_flag b.h1s.sd.flg sd "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]h1s\.flg=([0-9a-fx]*) ]]   || append_flag b.h1s.flg   h1s  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]h1c\.flg=([0-9a-fx]*) ]]   || append_flag b.h1c.flg   h1c  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ ^[[:blank:]]*\.sc=.*\.flg=.*\.app=.*\.sd=[^=]*\.flg=([0-9a-fx]*) ]] || append_flag b.h2s.sd.flg sd "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]h2s.*\.flg=([0-9a-fx]*) ]] || append_flag b.h2s.flg   h2s  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]h2c.*\.flg=([0-9a-fx]*) ]] || append_flag b.h2c.flg   h2c  "${BASH_REMATCH[1]}"
        elif [ $ctx = cob ]; then
                ! [[ "$REPLY" =~ [[:blank:]]flags=([0-9a-fx]*) ]]      || append_flag b.co.flg    conn "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]fd.state=([0-9a-fx]*) ]]   || append_flag b.co.fd.st  fd   0x"${BASH_REMATCH[1]}"
        elif [ $ctx = res ]; then
                ! [[ "$REPLY" =~ [[:blank:]]\(f=([0-9a-fx]*) ]]        || append_flag res.flg     chn  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]an=([0-9a-fx]*) ]]         || append_flag res.ana     ana  "${BASH_REMATCH[1]}"
                ! [[ "$REPLY" =~ [[:blank:]]htx.*flags=([0-9a-fx]*) ]] || append_flag res.htx.flg htx  "${BASH_REMATCH[1]}"
        fi

        out[${#out[@]}]="$REPLY"
done

# dump the last stream
dump_and_reset
