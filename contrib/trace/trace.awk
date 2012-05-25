#!/bin/sh
#
# trace.awk - Fast trace symbol resolver - w@1wt.eu - 2012/05/25
#
# Principle: this program launches reads pointers from a trace file and if not
# found in its cache, it passes them over a pipe to addr2line which is forked
# in a coprocess, then stores the result in the cache.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# usage: $0 exec_file < trace.out
#

if [ $# -lt 1 ]; then
  echo "Usage:   ${0##*/} exec_file < trace.out"
  echo "Example: ${0##*/} ./haproxy < trace.out"
  echo "Example: HAPROXY_TRACE=/dev/stdout ./haproxy -f cfg | ${0##*/} ./haproxy"
  exit 1
fi

if [ ! -s "$1" ]; then
  echo "$1 is not a valid executable file"
  exit 1
fi

exec awk -v prog="$1" \
'
BEGIN {
  if (cmd == "")
    cmd=ENVIRON["ADDR2LINE"];
  if (cmd == "")
    cmd="addr2line";

  if (prog == "")
    prog=ENVIRON["PROG"];

  cmd=cmd " -f -e " prog;

  for (i = 1; i < 100; i++) {
    indents[">",i] = indents[">",i-1] "->"
    indents[">",i-1] = indents[">",i-1] " "
    indents["<",i] = indents["<",i-1] "  "
    indents["<",i-1] = indents["<",i-1] " "
  }
}

function getptr(ptr)
{
  loc=locs[ptr];
  name=names[ptr];
  if (loc == "" || name == "") {
    print ptr |& cmd;
    cmd |& getline name;
    cmd |& getline loc;
    names[ptr]=name
    locs[ptr]=loc
  }
}

{
  # input format: <timestamp> <level> <caller> <dir> <callee>
  getptr($3); caller_loc=loc; caller_name=name
  getptr($5); callee_loc=loc; callee_name=name
  printf "%s %s  %s %s %s [%s:%s] %s [%s:%s]\n",
    $1, indents[$4,$2], caller_name, $4, callee_name, caller_loc, $3, $4, callee_loc, $5
}
'
