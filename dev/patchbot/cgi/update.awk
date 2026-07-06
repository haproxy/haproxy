#!/usr/bin/gawk -bf
#
# update.awk - storage backend for the patchbot backport review page
#
# Stores the human review edits (verdict overrides and notes) made on the
# patchbot HTML page into a per-branch file kept in a dedicated git
# repository, so that they are durable and shared between reviewers.
#
# This script is exec'd by a tiny "update.cgi" shell wrapper which is the
# only web-exposed piece and holds the deployment-specific configuration:
#
#     #!/bin/sh
#     exec /path/to/update.awk -r /path/to/repo
#
# The wrapper lives next to the generated HTML pages (thttpd must have the
# "**.cgi" pattern enabled so that it is executed, not served). This script,
# the repository and its .git must all stay OUTSIDE the HTTP document root.
# The repository is a plain git working tree with a configured committer
# identity, containing one file per major branch (e.g. "3.5") with one line
# per touched commit:
#
#     <commit_id> [state <n|u|w|y>] [notes "<escaped text>"]
#
# Commit ids are lowercase hex of any length; matching is symmetric-prefix
# (two ids designate the same commit iff one is a prefix of the other) and
# stops on the first match. Notes are double-quoted with '\' escaping '"'
# and '\'; no stored line may ever contain a newline. Malformed fields or
# lines are silently ignored, never fatal, and lines that are not being
# modified are preserved byte-for-byte (admin hand-edits are legal).
#
# Requests (regular CGI environment):
#   - POST update.cgi?branch=3.5 with a line-oriented body:
#         <cid> state <n|u|w|y|revert>
#         <cid> notes <text to append>
#         <cid> setnotes <hash> <replacement text>
#     "state" overrides the verdict, "revert" (aliases "same", "unchanged")
#     removes the override so the bot's verdict applies again, "notes"
#     appends to the commit's notes (capped to 500 chars per push). Broken
#     directives are dropped, the survivors are applied under the lock and
#     the result is committed to git. Neither directive carries a base/old
#     value: state is last-write-wins and notes are append-only, which is
#     what keeps concurrent edits conflict-free.
#     "setnotes" replaces the whole note blob (or deletes it when the text
#     is empty) and is the exception: <hash> is the SDBM hash (8 hex
#     chars) of the blob the client based its edit on, and the directive is
#     only applied if it still matches the stored blob. Otherwise it is
#     dropped and reported as a "conflict <cid>" line in the response, so
#     that a replacement can never silently destroy a concurrent update.
#   - GET update.cgi?branch=3.5 returns the current overlay as a JSON array
#     of {"cid": ..., "state": ..., "notes": ...} objects, with absent
#     fields omitted and notes fully unescaped (an empty overlay yields
#     "[]"), directly usable with JSON.parse() on the client.
#
# Requires GNU awk (PROCINFO, systime); the -b flag in the shebang makes all
# string operations byte-based regardless of the locale, which the escaping,
# the caps and the hash depend on. A few points deserve attention:
#   - external commands (git, mkdir, mv, kill) go through /bin/sh, so
#     everything interpolated into a command is shell-quoted with q();
#   - NUL bytes in inputs are not reliably preserved by awk; they can only
#     occur in malformed requests, which are tolerated, not honoured;
#   - writing through a redirection whose target cannot be opened is a
#     fatal error in awk, terminating us without even a response, so the
#     writes into the (stealable) lock dir are arranged to be immune: the
#     pid goes through the shell and the temp file is opened the instant
#     the lock is acquired, its descriptor surviving a later theft.
#
# The script always exits zero once a response has been emitted, including
# its own error responses, while a fatal awk error exits non-zero without
# any output: a supervising wrapper can thus safely map any non-zero
# termination to a generic error response.
#
# Fully testable from a shell without any HTTP server:
#
#     printf '%s\n' 'deadbeef1234 state y' 'deadbeef1234 notes checked' > body
#     REQUEST_METHOD=POST QUERY_STRING=branch=3.5 \
#         CONTENT_LENGTH=$(stat -c %s body) ./update.awk -r /path/to/repo < body

BEGIN {
	MAX_CID_LEN = 40        # bound on a commit id (full SHA-1)
	MAX_NOTE_LEN = 500      # cap on a single pushed note addition
	MAX_EDIT_LEN = 4000     # cap on a whole-blob replacement (setnotes)
	MAX_BRANCH_LEN = 15     # bound on the branch name
	MAX_BODY_LEN = 1048576  # bound on a POST body
	NOTE_SEP = "; "         # separator between coalesced notes
	LOCK_RETRIES = 100      # lock attempts before reporting busy
	LOCK_SLEEP = 0.05       # sleep between two attempts (~5s total)
	LOCK_STALE_AGE = 60     # age backstop when the pid file is unusable

	# byte value of every possible character, for escaping decisions
	for (i = 0; i < 256; i++)
		ORD[sprintf("%c", i)] = i

	# Arguments: -r <repo>. Note that when invoked through the shebang,
	# gawk itself consumes the leading "-r" (its --re-interval flag, a
	# no-op nowadays), and the repository path then reaches us as the
	# first bare operand: accept both forms.
	repo = ""
	for (i = 1; i < ARGC; i++) {
		if (ARGV[i] == "-r" && i + 1 < ARGC) {
			repo = ARGV[i + 1]
			ARGV[i] = ARGV[i + 1] = ""
			i++
		}
		else if (ARGV[i] != "" && repo == "") {
			repo = ARGV[i]
			ARGV[i] = ""
		}
		else if (ARGV[i] != "")
			die("500 Internal Server Error", \
			    "server misconfigured (usage: update.awk -r /path/to/repo)")
	}

	if (repo == "" || system("test -d " q(repo)) != 0)
		die("500 Internal Server Error", "server misconfigured")

	lock_path = repo "/lock"
	lock_pid = lock_path "/pid"
	lock_tmp = lock_path "/tmp"

	branch = get_branch()

	if (ENVIRON["REQUEST_METHOD"] == "POST")
		handle_post()
	else if (ENVIRON["REQUEST_METHOD"] == "GET")
		handle_get()
	else
		die("405 Method Not Allowed", "unsupported method")
	exit 0
}

# shell-quotes <s> so it can be safely interpolated into a command line:
# every external command goes through /bin/sh, this is the only protection.
function q(s)
{
	gsub(/'/, "'\\\\''", s)
	return "'" s "'"
}

# Prints a complete CGI error response and exits, releasing the lock if it
# was held. Nothing is ever written to stderr, here nor anywhere else:
# thttpd forwards the CGI's stderr to the client *before* its stdout, so
# anything written there would land ahead of the response headers and
# corrupt them; every diagnostic must be carried by the response itself.
function die(status, msg)
{
	if (lock_held)
		lock_release()
	printf "Status: %s\r\nContent-Type: text/plain\r\n\r\n%s\n", status, msg
	exit 0
}

# Extracts and validates the "branch" parameter from QUERY_STRING (used for
# both GET and POST). The strict digits-dot-digits pattern is the path
# traversal guard: the branch is the only request-controlled component of
# the storage file path and nothing else may ever reach the path building.
function get_branch(   n, i, p, v)
{
	n = split(ENVIRON["QUERY_STRING"], p, "&")
	v = ""
	for (i = 1; i <= n; i++) {
		if (substr(p[i], 1, 7) == "branch=") {
			v = substr(p[i], 8)
			break
		}
	}
	if (v == "" || length(v) > MAX_BRANCH_LEN || v !~ /^[0-9]+\.[0-9]+$/)
		die("400 Bad Request", "missing or invalid branch")
	return v
}

# SDBM hash of <s> (h = c + h * 65599) as 8 hex chars, the concurrency token
# carried by a note blob replacement; must match the page's JS version. The
# small multiplier keeps the 32-bit state exactly representable with awk's
# double-precision numbers (65599 * 2^32 stays well below 2^53).
function sdbm_hex(s,   h, i, n)
{
	h = 0
	n = length(s)
	for (i = 1; i <= n; i++)
		h = (ORD[substr(s, i, 1)] + h * 65599) % 4294967296
	return sprintf("%08x", h)
}

# Symmetric-prefix commit id match: two ids designate the same commit iff
# one is a prefix of the other. The caller scans in file order and stops on
# the first match; providing enough digits to stay unambiguous is the
# writer's responsibility (12 recommended). A too-short collision merely
# lands on the wrong line and is admin-fixable by editing the file.
function cid_match(a, b)
{
	return index(a, b) == 1 || index(b, a) == 1
}

# returns the leading commit id of a storage line (lowercase hex followed by
# a blank or the end of line), or "" if none parses
function line_cid(line,   c, nxt)
{
	sub(/^[ \t]+/, "", line)
	if (!match(line, /^[0-9a-f]+/))
		return ""
	c = substr(line, 1, RLENGTH)
	nxt = substr(line, RLENGTH + 1, 1)
	if (length(c) > MAX_CID_LEN || (nxt != "" && nxt != " " && nxt != "\t"))
		return ""
	return c
}

# Parses storage line <line> into P_cid/P_state/P_notes/P_has_notes. Returns
# 1 if a valid commit id was found (the entry is usable), 0 otherwise. Any
# broken or unknown field is silently dropped, never fatal, so that one bad
# hand-edit cannot break the whole file and future format additions don't
# trip older code.
function parse_line(line,   p, v, nxt, out, i, n, c, closed)
{
	P_cid = ""; P_state = ""; P_notes = ""; P_has_notes = 0

	P_cid = line_cid(line)
	if (P_cid == "")
		return 0
	sub(/^[ \t]+/, "", line)
	p = substr(line, length(P_cid) + 1)

	while (p != "") {
		sub(/^[ \t]+/, "", p)
		if (p == "")
			break

		if (match(p, /^state[ \t]+/)) {
			v = substr(p, RLENGTH + 1, 1)
			nxt = substr(p, RLENGTH + 2, 1)
			if (v ~ /^[nuwy]$/ && (nxt == "" || nxt == " " || nxt == "\t")) {
				P_state = v
				p = substr(p, RLENGTH + 2)
				continue
			}
			# unknown state value: drop the field
		}
		else if (match(p, /^notes[ \t]+"/)) {
			out = ""; closed = 0
			i = RLENGTH + 1
			n = length(p)
			while (i <= n) {
				c = substr(p, i, 1)
				if (c == "\"") {
					closed = 1
					i++
					break
				}
				if (c == "\\" && i < n) {
					i++
					c = substr(p, i, 1)
				}
				i++
				if (c == "\r")
					continue
				if (ORD[c] < 32 || ORD[c] == 127)
					c = " "
				out = out c
			}
			if (closed) {
				P_notes = out
				P_has_notes = 1
				p = substr(p, i)
				continue
			}
			# unterminated quote: drop the field and what follows,
			# it cannot be delimited
			break
		}
		# unknown or broken field: skip one token and try again
		sub(/^[^ \t]+/, "", p)
	}
	return 1
}

# formats an entry back into a storage line. Notes are quoted with '\'
# escaping '"' and '\'; as a hard invariant, no control char (and especially
# no newline) may ever be emitted inside a line, or the one-line-per-commit
# format breaks, so anything unexpected is defensively turned into a space.
function fmt_entry(cid, state, notes, has_notes,   line, out, i, n, c)
{
	line = cid
	if (state != "")
		line = line " state " state
	if (has_notes) {
		out = ""
		n = length(notes)
		for (i = 1; i <= n; i++) {
			c = substr(notes, i, 1)
			if (c == "\r")
				continue
			if (c == "\"" || c == "\\")
				out = out "\\" c
			else if (ORD[c] < 32 || ORD[c] == 127)
				out = out " "
			else
				out = out c
		}
		line = line " notes \"" out "\""
	}
	return line
}

# Sanitises a pushed note: CR is dropped, any other control char becomes a
# space (nothing may ever introduce a newline into a stored line), then the
# text is trimmed and capped to <cap> bytes on a UTF-8 character boundary.
function sanitize_note(s, cap,   b)
{
	gsub(/\r/, "", s)
	gsub(/[\x01-\x1f\x7f]/, " ", s)
	sub(/^ +/, "", s)
	sub(/ +$/, "", s)
	if (length(s) > cap) {
		# never cut in the middle of a UTF-8 sequence: back off while
		# the first dropped byte is a continuation byte (0x80-0xBF)
		b = ORD[substr(s, cap + 1, 1)]
		while (cap > 0 && b >= 128 && b < 192) {
			cap--
			b = ORD[substr(s, cap + 1, 1)]
		}
		s = substr(s, 1, cap)
		sub(/ +$/, "", s)
	}
	return s
}

# reads the POST body from stdin according to CONTENT_LENGTH
function read_body(   cl, body, line, got)
{
	if (ENVIRON["CONTENT_LENGTH"] !~ /^[0-9]+$/ || \
	    ENVIRON["CONTENT_LENGTH"] + 0 > MAX_BODY_LEN)
		die("400 Bad Request", "missing or invalid content length")
	cl = ENVIRON["CONTENT_LENGTH"] + 0

	body = ""; got = 0
	while (got < cl && (getline line < "/dev/stdin") > 0) {
		got += length(line) + length(RT)
		body = body line "\n"
	}
	if (got < cl)
		die("400 Bad Request", "truncated body")
	return body
}

# Parses the POST body into the d_* directive arrays. Broken directives are
# dropped, never fatal: a non-hex or over-long cid, an unknown verb or state
# value, or an empty note simply skip that line, and the survivors are still
# applied. Returns the number of valid directives.
function parse_directives(body,   nb, n, i, line, cid, rest, v, txt, h)
{
	nb = 0
	n = split(body, BL, "\n")
	for (i = 1; i <= n; i++) {
		line = BL[i]
		sub(/\r$/, "", line)
		sub(/^[ \t]+/, "", line)

		# the commit id is stored verbatim as sent by the client
		# (whatever length the page carries), only lowercased. The
		# length bound is the only enforcement.
		if (!match(line, /^[0-9a-fA-F]+[ \t]/))
			continue
		cid = tolower(substr(line, 1, RLENGTH - 1))
		if (length(cid) > MAX_CID_LEN)
			continue
		rest = substr(line, RLENGTH + 1)
		sub(/^[ \t]+/, "", rest)

		if (match(rest, /^state[ \t]+/)) {
			v = substr(rest, RLENGTH + 1)
			sub(/[ \t]+$/, "", v)
			if (v ~ /^[nuwy]$/) {
				nb++
				d_type[nb] = "state"; d_cid[nb] = cid; d_state[nb] = v
			}
			else if (v ~ /^(revert|same|unchanged)$/) {
				nb++
				d_type[nb] = "revert"; d_cid[nb] = cid
			}
			# else: unknown value or trailing junk, drop
		}
		else if (match(rest, /^notes[ \t]/)) {
			txt = sanitize_note(substr(rest, RLENGTH + 1), MAX_NOTE_LEN)
			if (txt == "")
				continue
			nb++
			d_type[nb] = "notes"; d_cid[nb] = cid; d_note[nb] = txt
		}
		else if (match(rest, /^setnotes[ \t]+/)) {
			v = substr(rest, RLENGTH + 1)
			if (!match(v, /^[0-9a-fA-F]{8}([ \t]|$)/))
				continue
			h = tolower(substr(v, 1, 8))
			txt = substr(v, 9)
			sub(/^[ \t]+/, "", txt)
			# an empty replacement is valid: it deletes the notes
			nb++
			d_type[nb] = "setnotes"; d_cid[nb] = cid
			d_hash[nb] = h
			d_note[nb] = sanitize_note(txt, MAX_EDIT_LEN)
		}
	}
	return nb
}

# loads the branch file into the L_* line arrays; a missing file is an empty
# one (first write will create it). Lines are kept verbatim; only the
# leading commit id is parsed here, for matching.
function load_file(fname,   line)
{
	nb_lines = 0
	while ((getline line < fname) > 0) {
		nb_lines++
		L_raw[nb_lines] = line
		L_cid[nb_lines] = line_cid(line)
		L_touched[nb_lines] = 0
	}
	close(fname)
}

# Applies directive <di>: the target line is looked up by prefix-match,
# first match wins, scanning the file lines then the new entries; a miss
# creates a new entry (except for a revert, which then has nothing to
# remove). A line reduced to neither state nor notes is dropped at write
# time. Returns 0 on success, or 1 when a setnotes base hash doesn't match
# the stored blob anymore: the directive is then not applied (a replacement
# must never silently destroy a concurrent update) and the caller reports
# the conflict.
function apply_directive(di,   i, li, ni, was_touched, cur)
{
	li = 0; ni = 0; was_touched = 0
	for (i = 1; i <= nb_lines; i++) {
		if (L_cid[i] == "" || !cid_match(L_cid[i], d_cid[di]))
			continue
		li = i
		was_touched = L_touched[i]
		if (!L_touched[i]) {
			parse_line(L_raw[i])
			L_state[i] = P_state
			L_notes[i] = P_notes
			L_has[i] = P_has_notes
			L_touched[i] = 1
		}
		break
	}
	if (!li) {
		for (i = 1; i <= nb_new; i++) {
			if (cid_match(N_cid[i], d_cid[di])) {
				ni = i
				break
			}
		}
	}

	# The base check happens before any entry creation or modification.
	# On conflict the line must be left exactly as found, including not
	# marked as modified if this lookup was what materialised it.
	if (d_type[di] == "setnotes") {
		cur = ""
		if (li && L_has[li])
			cur = L_notes[li]
		else if (ni && N_has[ni])
			cur = N_notes[ni]
		if (sdbm_hex(cur) != d_hash[di]) {
			if (li && !was_touched)
				L_touched[li] = 0
			return 1
		}
	}

	if (!li && !ni) {
		if (d_type[di] == "revert")
			return 0        # nothing stored for this commit anyway
		if (d_type[di] == "setnotes" && d_note[di] == "")
			return 0        # deleting non-existing notes
		nb_new++
		N_cid[nb_new] = d_cid[di]
		N_state[nb_new] = ""; N_notes[nb_new] = ""; N_has[nb_new] = 0
		ni = nb_new
	}

	if (d_type[di] == "state") {
		if (li) L_state[li] = d_state[di]; else N_state[ni] = d_state[di]
	}
	else if (d_type[di] == "revert") {
		if (li) L_state[li] = ""; else N_state[ni] = ""
	}
	else if (d_type[di] == "notes") {
		if (li) {
			L_notes[li] = L_has[li] ? L_notes[li] NOTE_SEP d_note[di] : d_note[di]
			L_has[li] = 1
		}
		else {
			N_notes[ni] = N_has[ni] ? N_notes[ni] NOTE_SEP d_note[di] : d_note[di]
			N_has[ni] = 1
		}
	}
	else if (d_type[di] == "setnotes") {
		if (li) {
			L_notes[li] = d_note[di]
			L_has[li] = (d_note[di] != "")
		}
		else {
			N_notes[ni] = d_note[di]
			N_has[ni] = (d_note[di] != "")
		}
	}
	return 0
}

# Serialises all writers around the branch files. The lock is a directory
# (mkdir is atomic) at an obvious fixed place, <repo>/lock, which also hosts
# the temp file so that the final rename stays on one filesystem. The
# holder's PID is stored inside; a dead holder is the real staleness signal
# (a live but slow one, e.g. during git gc, must never be evicted
# mid-commit), with a loose age backstop only for when no PID can be read.
#
# NOTE: PID-based takeover is a valid liveness signal only because all
# writers are local children of the same host (thttpd CGI processes). If
# another writer path is ever added (cron job, over-SSH update, push step
# touching this repo), the liveness check stops meaning "the holder is
# alive" and this takeover silently stops protecting the file.
#
# Returns 0 on success, -1 when the lock could not be obtained (busy).
function lock_acquire(   i, pid, stale, mt, priv, cmd, p2)
{
	for (i = 0; i < LOCK_RETRIES; i++) {
		if (system("mkdir " q(lock_path) " 2>/dev/null") == 0) {
			# The pid is written via the shell: a takeover based on
			# a stale decision may steal this fresh lock before the
			# pid lands, and a plain print into the vanished dir
			# would be a fatal awk error killing us without even a
			# response, while a command failure is just a lost
			# acquisition to retry.
			if (system("echo " PROCINFO["pid"] " > " q(lock_pid) " 2>/dev/null") != 0)
				continue
			lock_held = 1
			return 0
		}

		# The lock is held: check whether the holder is still alive.
		# All writers run under the same UID, so failing to signal it,
		# even with EPERM, means it is dead and its pid was recycled
		# by a foreign process; a wrongful eviction would anyway be
		# absorbed by the takeover verification and the victim's
		# retry. The pid file must be closed even when
		# the read fails (e.g. caught empty before the holder flushed
		# it): gawk keeps input files open and cached by path, and a
		# cached descriptor would keep returning the content of a
		# previous lock's deleted pid file, making a live holder look
		# dead and letting its lock be stolen in the middle of a write.
		pid = ""; stale = 0
		getline pid < lock_pid
		close(lock_pid)
		if (pid "" == PROCINFO["pid"] "")
			stale = 1       # our own lock, orphaned by a foiled takeover
		else if (pid ~ /^[0-9]+$/ && pid + 0 > 0)
			stale = (system("kill -0 " pid " 2>/dev/null") != 0)
		else {
			cmd = "stat -c %Y " q(lock_path) " 2>/dev/null"
			mt = ""
			cmd | getline mt
			close(cmd)
			stale = (mt ~ /^[0-9]+$/ && systime() - mt > LOCK_STALE_AGE)
		}

		if (stale) {
			# Atomic takeover: rename() has exactly one winner
			# (mv -T refuses an existing target), which owns the
			# recovery and discards the stale dir under its
			# private name; a loser re-enters acquisition. Never
			# rmdir-then-mkdir, that would race two adopters.
			#
			# The rename is atomic but the staleness decision was
			# not: between reading the dead holder's pid and the
			# rename, the lock may have been released and
			# re-acquired by a live writer, in which case we just
			# stole a live lock. So verify: only discard the
			# stolen dir if it still carries the pid we judged
			# dead, otherwise put it back untouched (its temp file
			# is still inside, the victim never notices anything).
			priv = repo "/lock.stale." PROCINFO["pid"] "." i
			if (system("mv -T " q(lock_path) " " q(priv) " 2>/dev/null") == 0) {
				p2 = ""
				getline p2 < (priv "/pid")
				close(priv "/pid")
				if (p2 "" == pid "")
					system("rm -f " q(priv "/pid") " " q(priv "/tmp") \
					       "; rmdir " q(priv) " 2>/dev/null")
				else
					# the give-back may fail if the path was
					# re-created in between; the private dir is
					# then left over for the admin, it cannot
					# be restored safely
					system("mv -T " q(priv) " " q(lock_path) " 2>/dev/null")
			}
			continue
		}
		system("sleep " LOCK_SLEEP)
	}
	return -1
}

# Runs "git -C <repo> <args>". Both its stdout and stderr are captured (into
# GITMSG, up to 255 bytes, control chars turned into spaces), so that git
# can neither corrupt the CGI response nor leak into a server which sends
# the CGI's stderr to the client, and above all so that the exact git error
# can be reported to the user. Since the command goes through /bin/sh, an
# unfindable git yields status 127 and the shell's own message, reworded to
# directly point at the typical PATH issue.
function run_git(args,   cmd, line, out, st)
{
	cmd = "git -C " q(repo) " " args " 2>&1"
	out = ""
	while ((cmd | getline line) > 0)
		out = out (out == "" ? "" : " ") line
	st = close(cmd)
	gsub(/[\x01-\x1f\x7f]/, " ", out)
	if (st == 127)
		out = "cannot execute git: " out
	GITMSG = substr(out, 1, 255)
	sub(/ +$/, "", GITMSG)
	return st
}

# Releases the lock, but only after checking that it is still ours: after a
# takeover interleaving gone wrong, the path may carry someone else's live
# lock, which must not be dismantled; ours is then a private stale dir that
# the next writers will reclaim. Also called from die().
function lock_release(   p)
{
	p = ""
	getline p < lock_pid
	close(lock_pid)
	if (p "" == PROCINFO["pid"] "")
		system("rm -f " q(lock_pid) " " q(lock_tmp) "; rmdir " q(lock_path) " 2>/dev/null")
	lock_held = 0
}

# The GET handler: returns the current overlay for <branch> as a JSON array
# of {"cid","state","notes"} objects with absent fields omitted; a missing
# or empty file yields "[]". The raw storage format never travels: notes
# are unescaped by the parser and JSON-escaped here, so the client can
# JSON.parse() the result and insert notes via textContent directly.
# Unparseable content is silently skipped. Reads are lockless: the atomic
# rename on the write side guarantees the file is always a complete valid
# version.
function handle_get(   i, first, out)
{
	load_file(repo "/" branch)

	printf "Content-Type: application/json\r\nCache-Control: no-store\r\n\r\n"
	out = "["
	first = 1
	for (i = 1; i <= nb_lines; i++) {
		if (L_cid[i] == "" || !parse_line(L_raw[i]))
			continue
		if (P_state == "" && !P_has_notes)
			continue        # nothing stored for this commit
		if (!first)
			out = out ","
		first = 0
		out = out "\n{\"cid\":" json_str(P_cid)
		if (P_state != "")
			out = out ",\"state\":\"" P_state "\""
		if (P_has_notes)
			out = out ",\"notes\":" json_str(P_notes)
		out = out "}"
	}
	printf "%s%s]\n", out, first ? "" : "\n"
}

# emits <s> as a JSON string; control chars are defensively encoded and
# UTF-8 sequences pass through verbatim
function json_str(s,   out, i, n, c)
{
	out = "\""
	n = length(s)
	for (i = 1; i <= n; i++) {
		c = substr(s, i, 1)
		if (c == "\"" || c == "\\")
			out = out "\\" c
		else if (ORD[c] < 32)
			out = out sprintf("\\u%04x", ORD[c])
		else
			out = out c
	}
	return out "\""
}

# the POST handler: parse directives, and if any survives, apply them to the
# branch file under the lock, atomically replace it and commit it to git.
function handle_post(   body, i, j, fname, nb_confl, nb_done, msg, git_failed, attempt, renamed)
{
	body = read_body()
	nb_dirs = parse_directives(body)
	if (nb_dirs == 0) {
		# nothing valid remains: complete no-op, no lock taken
		printf "Content-Type: text/plain\r\n\r\nOK 0 directives applied\n"
		return
	}

	# The whole locked cycle may have to be redone: if our lock (and the
	# temp file inside it) is stolen by a takeover which mistook us for
	# dead, the final rename fails while nothing was applied to the file
	# yet, so it is always safe to start over from a fresh read.
	fname = repo "/" branch
	renamed = 0
	for (attempt = 0; attempt < 5 && !renamed; attempt++) {
		if (lock_acquire() < 0)
			die("503 Service Unavailable", "busy, retry")

		# Open the temp file right away: from here on its descriptor
		# keeps working even if the lock gets stolen (the final rename
		# will fail cleanly and be retried). Opening it later would
		# widen the window where a theft makes the redirection open
		# fail, which is a fatal error in awk.
		printf "" > lock_tmp

		# the file may contain admin hand-edits, possibly not even committed
		# yet: read it as it is, preserve every line we're not touching, and
		# commit whatever ends up in the tree.
		delete L_raw; delete L_cid; delete L_touched
		delete L_state; delete L_notes; delete L_has
		delete N_cid; delete N_state; delete N_notes; delete N_has
		delete CONFL; delete DONE
		load_file(fname)

		nb_new = 0; nb_confl = 0; nb_done = 0
		for (i = 1; i <= nb_dirs; i++) {
			if (apply_directive(i)) {
				nb_confl++
				CONFL[nb_confl] = d_cid[i]
				continue
			}
			# remember the touched commits for the git commit message
			for (j = 1; j <= nb_done; j++)
				if (DONE[j] == d_cid[i])
					break
			if (j > nb_done)
				DONE[++nb_done] = d_cid[i]
	}

	git_failed = 0
	GITMSG = ""
	renamed = 1
	if (nb_confl < nb_dirs) {
		# Complete the temp file (opened right when the lock was
		# acquired: the open descriptor is immune to a lock theft, the
		# writes land in the renamed-away file and the rename below
		# then fails cleanly) and atomically rename() it over the
		# branch file, so that the latter is always a complete valid
		# file, even across a crash.
		for (i = 1; i <= nb_lines; i++) {
			if (!L_touched[i])
				print L_raw[i] > lock_tmp
			else if (L_state[i] != "" || L_has[i])
				print fmt_entry(L_cid[i], L_state[i], L_notes[i], L_has[i]) > lock_tmp
			# else: line reduced to nothing, dropped
		}
		for (i = 1; i <= nb_new; i++) {
			if (N_state[i] != "" || N_has[i])
				print fmt_entry(N_cid[i], N_state[i], N_notes[i], N_has[i]) > lock_tmp
		}
		close(lock_tmp)
		system("sync -d " q(lock_tmp) " 2>/dev/null")
		if (system("mv -T " q(lock_tmp) " " q(fname) " 2>/dev/null") != 0) {
			# our lock was stolen and the temp file went with it:
			# what now sits at the lock path belongs to someone
			# else, leave it alone and redo the whole cycle from a
			# fresh read
			lock_held = 0
			renamed = 0
			continue
		}

		# The commit subject names the branch and the first touched
		# commit (plus how many others), and the body lists all of
		# them one per line, which helps a lot when hand-editing the
		# storage repository (e.g. to locate a change when rebasing).
		msg = "update " branch ": " DONE[1]
		if (nb_done > 1)
			msg = msg " + " (nb_done - 1) " more"
		msg = msg "\n"
		for (i = 1; i <= nb_done; i++)
			msg = msg "\n" DONE[i]

		# Commit failures (e.g. missing committer identity) are not
		# fatal: the tree stays valid-but-uncommitted and the next
		# writer folds it into its own commit. But they must not stay
		# invisible either or the history silently stops being
		# recorded, so they are reported as a warning line in the
		# response. A no-op (identical content, e.g. re-pushed
		# identical states) is not a failure: the commit is simply
		# skipped when nothing is staged. Never checkout or reset
		# here, it would eat an admin's uncommitted hand-edit.
		if (run_git("add -- " q(branch)) != 0)
			git_failed = 1
		else if (run_git("diff --cached --quiet") != 0 && \
		         run_git("commit -q -m " q(msg)) != 0)
			git_failed = 1
	}
	# else: everything conflicted, nothing changed, nothing to write

	lock_release()
	}
	if (!renamed)
		die("500 Internal Server Error", "cannot replace branch file")

	# echo the conflicts then the resulting line(s) after the status; the
	# client relies on the "conflict <cid>" lines, the rest is mostly for
	# debugging.
	printf "Content-Type: text/plain\r\n\r\n"
	printf "OK %d directive%s applied\n", nb_dirs - nb_confl, \
	       nb_dirs - nb_confl == 1 ? "" : "s"
	for (i = 1; i <= nb_confl; i++)
		print "conflict " CONFL[i]
	if (git_failed)
		print "warning: git commit failed, history not recorded (" \
		      (GITMSG != "" ? GITMSG : \
		       "check the committer identity and permissions in the storage repository") ")"
	for (i = 1; i <= nb_lines; i++) {
		if (!L_touched[i])
			continue
		if (L_state[i] != "" || L_has[i])
			print fmt_entry(L_cid[i], L_state[i], L_notes[i], L_has[i])
		else
			print L_cid[i] " removed"
	}
	for (i = 1; i <= nb_new; i++) {
		if (N_state[i] != "" || N_has[i])
			print fmt_entry(N_cid[i], N_state[i], N_notes[i], N_has[i])
	}
}
