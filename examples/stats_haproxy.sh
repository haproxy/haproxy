#!/bin/bash

## contrib by prizee.com

socket='/var/run/haproxy.stat'

if ! type socat >/dev/null 2>&1 ; then
    echo "can't find socat in PATH" 1>&2
    exit 1
fi

printUsage ()
{
    echo -e "Usage : $(basename $0) [options] -s section
--section -s section\t: section to use ( --list format)
Options :
--socket -S [socket]\t: socket to use (default: /var/run/haproxy.stat)
--list -l\t\t: print available sections
--help -h\t\t: print this  message"
}

getRawStat ()
{
    if [ ! -S $socket ] ; then
	echo "$socket socket unavailable" 1>&2
	exit 1
    fi

    if ! printf "show stat\n" | socat unix-connect:${socket} stdio | grep -v "^#" ; then
	echo "cannot read $socket" 1>&2
	exit 1
    fi
}

getStat ()
{
    stats=$(getRawStat | grep $1 | awk -F "," '{print $5" "$8}')
    export cumul=$(echo $stats | cut -d " " -f2)
    export current=$(echo $stats | cut -d " " -f1)
}

showList ()
{
    getRawStat | awk -F "," '{print $1","$2}'
}

set -- `getopt -u -l socket:,section:,list,help -- s:S:lh "$@"`

while true ; do
    case $1 in
	--socket|-S) socket=$2 ; shift 2 ;;
	--section|-s) section=$2 ; shift 2 ;;
	--help|-h) printUsage ; exit 0 ;;
	--list|-l) showList ; exit 0 ;;
	--) break ;;
    esac
done

if [ "$section" = "" ] ; then
    echo "section not specified, run '$(basename $0) --list' to know available sections" 1>&2
    printUsage
    exit 1
fi

cpt=0
totalrate=0
while true ; do
    getStat $section
    if [ "$cpt" -gt "0" ] ; then
	sessionrate=$(($cumul-$oldcumul))
	totalrate=$(($totalrate+$sessionrate))
	averagerate=$(($totalrate/$cpt))
	printf "$sessionrate sessions/s (avg: $averagerate )\t$current concurrent sessions\n"
    fi
    oldcumul=$cumul
    sleep 1
    cpt=$(($cpt+1))
done
