#!/bin/sh
#
# Stores a compressed symbol table into an already linked ELF file.
#
# Copyright (C) 2026 HAProxy Technologies
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# The table describes the file it is stored in, so it can only be produced once
# that file is linked, and storing it must not move anything. The table is
# therefore appended at the end, the .gnu_debugdata section header reserved at
# link time is pointed at it so that gdb finds it by name, and the note segment
# reserved at link time is turned into a loadable one covering it, so that it is
# also readable from memory alone. The address is picked past everything the
# file already maps.
#
# usage: minidbg.sh <elf> <table>

: "${READELF:=readelf}"

elf="$1"
pay="$2"
# The loader maps the segment with mmap(), which needs its file offset and its
# address to be congruent modulo the page size of the machine that runs it, not
# of the one that builds it. Aligning both to the largest page size in use (64 kB
# on arm64 and ppc64) satisfies every smaller one as well, at the cost of at most
# that much padding once.
PAGE=65536

die() { echo "minidbg: $1" >&2; exit 1; }

[ $# = 2 ] || die "usage: $0 <elf> <table>"

hdr=$(LC_ALL=C "$READELF" -hW "$elf") || die "cannot read $elf"
case "$hdr" in
	*ELF64*) w=8 ;;
	*ELF32*) w=4 ;;
	*)       die "unknown ELF class" ;;
esac
case "$hdr" in
	*"big endian"*) be=1 ;;
	*)              be=0 ;;
esac
# an empty value would silently be taken as zero by the arithmetic below, so
# everything read from the listings is checked before being used
num() {
	case "$2" in
		'' | *[!0-9]*) die "cannot read the $1 of $elf from $READELF" ;;
	esac
}

phoff=$(echo "$hdr"     | awk '/Start of program header/ { print $(NF-3) }')
phentsize=$(echo "$hdr" | awk '/Size of program header/  { print $(NF-1) }')
shoff=$(echo "$hdr"     | awk '/Start of section header/ { print $(NF-3) }')
shentsize=$(echo "$hdr" | awk '/Size of section header/  { print $(NF-1) }')
num "program header offset" "$phoff"
num "program header size"   "$phentsize"
num "section header offset" "$shoff"
num "section header size"   "$shentsize"

# the two placeholders: the section gives the name, the note gives the segment.
# Their index in the listing is not their index in the table, so the section is
# located by the number readelf prints, and the note by where it starts.
secs=$(LC_ALL=C "$READELF" -SW "$elf") || die "cannot read the sections of $elf"
sec=$(echo "$secs" | awk '{ for (i = 1; i < NF; i++) if ($i == ".gnu_debugdata") {
				n = (i == 2) ? $1 : $(i - 1); gsub(/[][]/, "", n); print n; exit } }')
[ -n "$sec" ] || die "no .gnu_debugdata section in $elf, was it reserved at link time?"
num "section index" "$sec"
note=$(echo "$secs" | awk '{ for (i = 1; i < NF; i++) if ($i == ".note.hapdbg") {
				o = $(i + 3); z = $(i + 4); sub(/^0*/, "", o); sub(/^0*/, "", z)
				print o " " z; exit } }')
[ -n "$note" ] || die "no .note.hapdbg section in $elf, was it reserved at link time?"

# the note's own segment is the one that starts where the note does and holds
# nothing else, so that turning it into a loadable one loses no other note
segs=$(LC_ALL=C "$READELF" -lW "$elf") || die "cannot read the segments of $elf"
seg=$(echo "$segs" | awk -v want="$note" '
	$2 ~ /^0x/ && $3 ~ /^0x/ && $4 ~ /^0x/ {
		if ($1 == "NOTE") {
			o = $2; z = $5; sub(/^0x0*/, "", o); sub(/^0x0*/, "", z)
			if (o " " z == want) { print idx; exit }
		}
		idx++
	}')
[ -n "$seg" ] || die "the note of $elf has no segment of its own"
num "segment index" "$seg"

# the table is mapped past everything the file already maps
maxva=0
for e in $(echo "$segs" | awk '$1 == "LOAD" && $3 ~ /^0x/ { print $3 "+" $6 }'); do
	e=$(( $e ))
	[ $e -gt $maxva ] && maxva=$e
done
[ $maxva -gt 0 ] || die "$elf has no loadable segment"

paylen=$(wc -c < "$pay") || die "cannot read $pay"
[ "$paylen" -gt 0 ] || die "$pay is empty"
elflen=$(wc -c < "$elf")
off=$(( (elflen + PAGE - 1) / PAGE * PAGE ))
vaddr=$(( (maxva + PAGE - 1) / PAGE * PAGE ))

# writes <size> bytes of <value> at <offset>, in the file's byte order
# Use escapes in the format: BSD printf's %b truncates at NUL bytes.
wr() {
	_o=$1; _s=$2; _v=$3; _i=0; _e=''
	while [ $_i -lt $_s ]; do
		_b=$(printf '\\%03o' $(( (_v >> (8 * _i)) & 255 )))
		if [ "$be" = 1 ]; then _e="$_b$_e"; else _e="$_e$_b"; fi
		_i=$(( _i + 1 ))
	done
	printf "$_e" | dd of="$elf" bs=1 seek=$_o conv=notrunc 2>/dev/null ||
		die "cannot patch $elf"
}

# append at a page-aligned end, so that offset and address stay congruent
dd if=/dev/zero bs=1 count=$(( off - elflen )) 2>/dev/null >> "$elf" || die "cannot pad $elf"
cat "$pay" >> "$elf" || die "cannot append the table to $elf"

if [ $w = 8 ]; then
	sh_type=4; sh_flags=8; sh_addr=16; sh_off=24; sh_size=32; sh_align=48
	ph_type=0; ph_flags=4; ph_off=8; ph_va=16; ph_pa=24; ph_fsz=32; ph_msz=40; ph_align=48
else
	sh_type=4; sh_flags=8; sh_addr=12; sh_off=16; sh_size=20; sh_align=32
	ph_type=0; ph_off=4; ph_va=8; ph_pa=12; ph_fsz=16; ph_msz=20; ph_flags=24; ph_align=28
fi

s=$(( shoff + sec * shentsize ))
wr $(( s + sh_type ))  4  1		# SHT_PROGBITS
wr $(( s + sh_flags )) $w 2		# SHF_ALLOC
wr $(( s + sh_addr ))  $w $vaddr
wr $(( s + sh_off ))   $w $off
wr $(( s + sh_size ))  $w $paylen
wr $(( s + sh_align )) $w 16

p=$(( phoff + seg * phentsize ))
wr $(( p + ph_type ))  4  1		# PT_LOAD
wr $(( p + ph_flags )) 4  4		# PF_R
wr $(( p + ph_off ))   $w $off
wr $(( p + ph_va ))    $w $vaddr
wr $(( p + ph_pa ))    $w $vaddr
wr $(( p + ph_fsz ))   $w $paylen
wr $(( p + ph_msz ))   $w $paylen
wr $(( p + ph_align )) $w $PAGE
