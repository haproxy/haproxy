#!/bin/sh
# Example deployment wrapper for the storage backend of the patchbot review
# page. This wrapper is the only web-exposed piece: copy it next to the
# generated HTML pages (the page reaches it with a bare relative URL),
# adjust the paths below, and make sure the web server has the "**.cgi"
# pattern enabled so that this file is executed, not served (or its content,
# including the repository path, would leak).
#
# All deployment-specific settings belong here, as arguments: the backend
# itself (update.bin or update.awk, both honour the same interface) and the
# overlay git repository (with a configured committer identity) must both
# stay outside the document root.
#
# The wrapper supervises the backend rather than exec'ing it, relying on a
# simple contract: the backend always exits zero once it has emitted a
# response (including its own error responses), so any other termination
# means no response was produced (e.g. a fatal interpreter error) and a
# generic error is emitted instead, so that the browser always receives a
# response. The backend computes everything before emitting its response in
# one final burst, so a death with partial output is not a realistic case
# (and would anyway yield an unparsable response that the page treats as a
# failed save with the edits kept). The backend's stderr is discarded
# because the web server would send it to the client ahead of the response
# headers and corrupt them; point it to a file instead of /dev/null when
# debugging.

# The web server usually starts CGIs with a restricted compile-time PATH
# (e.g. thttpd's CGI_PATH): make sure it contains git, or adjust it here,
# otherwise nothing gets committed in the storage repository.
PATH=/usr/local/bin:/usr/bin:/bin
export PATH

# where the backend lives (update.awk or update.bin), and the storage repo
SCRIPTS_DIR=/home/patchbot/prog/bin
REPO_DIR=/home/patchbot/data/overlay

if ! "$SCRIPTS_DIR/update.awk" -r "$REPO_DIR" 2>/dev/null; then
	printf 'Status: 500 Internal Server Error\r\n'
	printf 'Content-Type: text/plain\r\n\r\n'
	printf 'backend error, nothing was saved\n'
fi
