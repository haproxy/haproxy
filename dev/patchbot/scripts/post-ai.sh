#!/bin/bash

####
#### Todo:
####   - change line color based on the selected radio button
####   - support collapsing lines per color/category (show/hide for each)
####   - add category "next" and see if the prompt can handle that (eg: d3e379b3)
####   - produce multiple lists on output (per category) allowing to save batches
####

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

USAGE="Usage: ${0##*/} [ -h ] [ -b 'bkp_list' ] [ -v version ] patch..."
MYSELF="$0"
GITURL="http://git.haproxy.org/?p=haproxy.git;a=commitdiff;h="
ISSUES="https://github.com/haproxy/haproxy/issues/"
BKP=""
VERSION=""

while [ -n "$1" -a -z "${1##-*}" ]; do
	case "$1" in
		-h|--help) quit "$USAGE" ;;
		-b)        BKP="$2"; shift 2 ;;
		-v)        VERSION="$2"; shift 2 ;;
		*)         die  "$USAGE" ;;
	esac
done

# VERSION is the branch this page covers (eg: 3.5). It is only used by the
# in-page JS to sync the review state with the server-side update.cgi, which
# strictly validates it, so let's check it here as well. When empty, the
# syncing UI is not emitted at all and the page keeps working standalone.
if [ -n "$VERSION" ] && ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
	die "Invalid version '$VERSION', expected <digits>.<digits>"
fi

PATCHES=( "$@" )

if [ ${#PATCHES[@]} = 0 ]; then
        die "$USAGE"
fi

# BKP is a space-delimited list of 8-char commit IDs, we'll
# assign them to the local bkp[] associative array.

declare -A bkp

for cid in $BKP; do
    bkp[$cid]=1
done

# some colors
BG_B="#e0e0e0"
BT_N="gray";     BG_N="white"
BT_U="#00e000";  BG_U="#e0ffe0"
BT_W="#0060ff";  BG_W="#e0e0ff"
BT_Y="red";      BG_Y="#ffe0e0"

echo "<HTML>"

cat <<- EOF
<HEAD><style>
input.n[type="radio"] {
  appearance: none;
  width: 1.25em;
  height: 1.25em;
  border-radius: 50%;
  border: 3px solid $BT_N;
  background-color: transparent;
}
input.n[type="radio"]:checked {
  appearance: none;
  width: 1.25em;
  height: 1.25em;
  border-radius: 50%;
  border: 2px solid black;
  background-color: $BT_N;
}

input.u[type="radio"] {
  appearance: none;
  width: 1.25em;
  height: 1.25em;
  border-radius: 50%;
  border: 3px solid $BT_U;
  background-color: transparent;
}
input.u[type="radio"]:checked {
  appearance: none;
  width: 1.25em;
  height: 1.25em;
  border-radius: 50%;
  border: 2px solid black;
  background-color: $BT_U;
}

input.w[type="radio"] {
  appearance: none;
  width: 1.25em;
  height: 1.25em;
  border-radius: 50%;
  border: 3px solid $BT_W;
  background-color: transparent;
}
input.w[type="radio"]:checked {
  appearance: none;
  width: 1.25em;
  height: 1.25em;
  border-radius: 50%;
  border: 2px solid black;
  background-color: $BT_W;
}

input.y[type="radio"] {
  appearance: none;
  width: 1.25em;
  height: 1.25em;
  border-radius: 50%;
  border: 3px solid $BT_Y;
  background-color: transparent;
}
input.y[type="radio"]:checked {
  appearance: none;
  width: 1.25em;
  height: 1.25em;
  border-radius: 50%;
  border: 2px solid black;
  background-color: $BT_Y;
}

/* shared reviewers' notes, shown below the AI explanation */
div.notes {
  font-style: italic;
  margin-top: 2px;
}
</style>

<script type="text/javascript"><!--

var cgi_url = "cgi-bin/update.cgi";
var nb_patches = 0;
var cid = [];
var bkp = [];

// the branch this page covers (eg: "3.5"), used to sync the review state
// with the server-side update.cgi; empty when generated without -v, in
// which case no syncing is possible and the page works standalone.
var branch = '$VERSION';

// Three states exist per line. The original state (orig[]) is the verdict
// the bot chose, captured at load time and constant. The reference state
// (ref_state[]/ref_notes[]) is the last known shared state, i.e. what the
// server last told us, on top of which the user's edits sit; it starts
// equal to the original and is only advanced by "Get updates" and by a
// successful save. The local state is the DOM itself (the checked radios),
// there is no separate copy. Nothing is fetched automatically: the user
// explicitly clicks "Get updates" to retrieve the shared state.
var orig = [];
var ref_state = [];
var ref_notes = [];
var cidmap = {};

// Note edition state per line: mode 0 = closed, 1 = appending (the input
// holds text to add to the shared notes), 2 = editing (the input holds the
// whole replacement blob, and note_base[] snapshots the reference it was
// based on; its hash is sent with the replacement so the server can refuse
// it if the blob changed concurrently). An open input only disappears once
// its content is synchronized with the reference: a successful save, an
// update proving an exact match, or an explicit cancel.
var note_mode = [];
var note_base = [];

// SDBM hash (h = c + h * 65599) of a string's UTF-8 bytes, as 8 hex chars;
// the concurrency token sent with a note replacement. Must match the
// server's C version; the small multiplier keeps the 32-bit state exact
// with JS doubles (65599 * 2^32 stays well below 2^53).
function sdbm(s) {
  var b = new TextEncoder().encode(s);
  var h = 0;
  var i;

  for (i = 0; i < b.length; i++)
    h = (b[i] + h * 65599) % 4294967296;
  return (h + 0x100000000).toString(16).slice(-8);
}

// returns the letter of the checked verdict radio of line <i>, or ""
function cur_state(i) {
  if (document.getElementById("bt_" + i + "_n").checked) return "n";
  if (document.getElementById("bt_" + i + "_u").checked) return "u";
  if (document.getElementById("bt_" + i + "_w").checked) return "w";
  if (document.getElementById("bt_" + i + "_y").checked) return "y";
  return "";
}

// checks the verdict radio <s> of line <i> (authoritative set, idempotent)
function set_state(i, s) {
  var el = document.getElementById("bt_" + i + "_" + s);
  if (el)
    el.checked = true;
}

// Returns the verdict letter emitted in the page for line <i>, i.e. the
// bot's verdict. It relies on defaultChecked, which reflects the "checked"
// attribute present in the HTML and not the radio's current state: across
// a reload, the browser restores the radios to the user's last local
// state, so looking at cur_state() at load time would wrongly capture the
// user's own edits as being the original state.
function gen_state(i) {
  if (document.getElementById("bt_" + i + "_n").defaultChecked) return "n";
  if (document.getElementById("bt_" + i + "_u").defaultChecked) return "u";
  if (document.getElementById("bt_" + i + "_w").defaultChecked) return "w";
  if (document.getElementById("bt_" + i + "_y").defaultChecked) return "y";
  return "";
}

// captures the bot's verdicts once the table is fully loaded: they preset
// both the original and the reference states. After a reload, the radios
// (and thus the local state) may differ from the bot's verdicts since the
// browser restores them: this is desired, such differences are unsaved
// local edits and must remain detected as such.
function init_ref() {
  var i, el;

  for (i = 1; i < nb_patches; i++) {
    orig[i] = gen_state(i);
    ref_state[i] = orig[i];
    ref_notes[i] = "";
    cidmap[cid[i]] = i;

    // the browser may also have restored an unsaved note into the hidden
    // input: reveal it so that it remains visible and editable instead of
    // being invisible yet silently pushed on the next save. The edition
    // mode did not survive the reload, so assume a plain addition, which
    // never destroys anything.
    el = document.getElementById("in_" + i);
    if (el && el.value) {
      note_mode[i] = 1;
      el.style.display = "";
    }
    upd_note_links(i);
  }
  updt_save_btn();
}

// the status line and the save button exist twice, at the top and at the
// bottom of the page, so both instances are always updated together
function sync_msg(m) {
  var el = document.getElementById("sync_msg");
  if (el)
    el.innerText = m;
  el = document.getElementById("sync_msg2");
  if (el)
    el.innerText = m;
}

// renders the reference notes of line <i> by replacing the whole container
// (never appending), so that re-applying the same notes is idempotent.
function show_notes(i) {
  var el = document.getElementById("notes_" + i);
  if (el)
    el.innerText = ref_notes[i] ? "Notes: " + ref_notes[i] : "";
}

// resolves a commit id received from the server to a line number: exact
// match first (the normal case), then symmetric-prefix (one id is a prefix
// of the other, which only happens with mixed-length ids), first line wins.
// Returns 0 when unknown (eg: a commit which is not on this page).
function find_line(ocid) {
  var i;

  if (cidmap[ocid])
    return cidmap[ocid];
  for (i = 1; i < nb_patches; i++)
    if (cid[i].startsWith(ocid) || ocid.startsWith(cid[i]))
      return i;
  return 0;
}

// Applies a freshly fetched overlay (the complete list of shared entries).
// The new reference of every line is recomputed as "the server's entry if
// any, otherwise the bot's original verdict", so that an entry removed on
// the server properly falls back to the original. The reference always
// advances, but the displayed state only moves where the user had no local
// edit: local edits win and will overwrite the shared state at save time.
function apply_ref(list) {
  var over_state = [], over_notes = [], claimed = [];
  var i, j, e, el, newref, newnotes, oldnotes;

  for (j = 0; j < list.length; j++) {
    e = list[j];
    i = find_line(String(e.cid));
    if (!i || claimed[i])
      continue;
    claimed[i] = 1;
    if (e.state)
      over_state[i] = String(e.state);
    if (e.notes)
      over_notes[i] = String(e.notes);
  }

  for (i = 1; i < nb_patches; i++) {
    newref = over_state[i] ? over_state[i] : orig[i];
    if (newref != ref_state[i] && ref_state[i] == cur_state(i))
      set_state(i, newref);
    ref_state[i] = newref;

    oldnotes = ref_notes[i];
    newnotes = over_notes[i] ? over_notes[i] : "";
    if (newnotes != oldnotes) {
      ref_notes[i] = newnotes;
      show_notes(i);
    }

    // Reconcile an open note box with the new reference: a box whose
    // content is now synchronized disappears (an addition someone already
    // pushed, or an edition matching the current notes); an edition whose
    // base moved is re-based on the new reference and marked red so the
    // user reviews it against the updated notes above before saving.
    if (note_mode[i]) {
      el = document.getElementById("in_" + i);
      if (note_mode[i] == 1 && el.value &&
          newnotes == (oldnotes ? oldnotes + "; " + el.value : el.value)) {
        cancel_note(i);
      }
      else if (note_mode[i] == 2) {
        if (el.value == newnotes)
          cancel_note(i);
        else if (note_base[i] != newnotes) {
          note_base[i] = newnotes;
          mark_conflict(i, 1);
        }
      }
    }
    upd_note_links(i);
  }
  updt_table(0);
  updt_output();
  updt_save_btn();
}

// "Get updates" button: fetches the current shared state from the server
function fetch_ref() {
  var i, el;

  if (!branch)
    return;

  // first silently close the no-op note boxes (opened but nothing changed,
  // e.g. an "edit" clicked by mistake): they hold nothing worth preserving
  // and would otherwise ambiguously survive while the notes displayed
  // above them change.
  for (i = 1; i < nb_patches; i++) {
    if (!note_mode[i])
      continue;
    el = document.getElementById("in_" + i);
    if (note_mode[i] == 1 && !el.value.trim())
      cancel_note(i);
    else if (note_mode[i] == 2 && el.value == note_base[i])
      cancel_note(i);
  }

  sync_msg("fetching...");
  fetch(cgi_url + "?branch=" + branch)
    .then(function(r) { if (!r.ok) throw 0; return r.json(); })
    .then(function(list) { apply_ref(list); sync_msg("reference updated"); })
    .catch(function() { sync_msg("fetch failed (server unreachable?)"); });
}

// shows/hides the per-line note links according to the edition mode and to
// the presence of reference notes ("edit note" needs something to edit, or
// a pending addition to merge; "cancel" needs an open input)
function upd_note_links(i) {
  var m = note_mode[i] ? note_mode[i] : 0;
  var el;

  el = document.getElementById("ln_add_" + i);
  if (el)
    el.style.display = m == 0 ? "" : "none";
  el = document.getElementById("ln_edit_" + i);
  if (el)
    el.style.display = (m == 0 && ref_notes[i]) || m == 1 ? "" : "none";
  el = document.getElementById("ln_cancel_" + i);
  if (el)
    el.style.display = m != 0 ? "" : "none";
}

// marks/unmarks the note input of line <i> as conflicting (red): the
// reference changed under the edit, the user must review the current notes
// above against the input's content before saving again.
function mark_conflict(i, on) {
  var el = document.getElementById("in_" + i);

  if (el)
    el.style.backgroundColor = on ? "#ffc0c0" : "";
}

// "[add note]" link: reveals the extra-notes input of line <i> in append
// mode; the text it holds will be appended to the shared notes on save
function add_note(i) {
  var el = document.getElementById("in_" + i);

  if (!el)
    return;
  note_mode[i] = 1;
  el.maxLength = 500;
  el.style.display = "";
  el.focus();
  upd_note_links(i);
  updt_save_btn();
}

// "[edit note]" link: switches line <i> to edition of the whole note blob
// (which a save sends as a replacement); a pending addition is merged in so
// nothing typed so far is lost. The reference blob is snapshotted as the
// base of the edit for the conflict detection.
function edit_note(i) {
  var el = document.getElementById("in_" + i);
  var txt;

  if (!el)
    return;
  txt = ref_notes[i];
  if (note_mode[i] == 1 && el.value)
    txt = txt ? txt + "; " + el.value : el.value;
  note_mode[i] = 2;
  note_base[i] = ref_notes[i];
  el.value = txt;
  el.maxLength = 4000;
  el.style.display = "";
  el.focus();
  upd_note_links(i);
  updt_save_btn();
}

// "[cancel]" link: closes the note input of line <i> without sending
// anything; also used internally once an input is known synchronized.
function cancel_note(i) {
  var el = document.getElementById("in_" + i);

  if (el) {
    el.value = "";
    el.style.display = "none";
  }
  note_mode[i] = 0;
  note_base[i] = "";
  mark_conflict(i, 0);
  upd_note_links(i);
  updt_save_btn();
}

// Grays the "Save changes" button when nothing differs from the reference
// (no verdict change, no pending note addition or edition), so it is
// visible at a glance whether anything remains to be saved. Called after
// every action which may change that: verdict clicks, note box openings,
// closings and typing, updates and saves. Bails out at the first pending
// change so the common case stays cheap.
function updt_save_btn() {
  var btn = document.getElementById("save_btn");
  var btn2 = document.getElementById("save_btn2");
  var pending = false;
  var i, s, el;

  if (!btn)
    return;
  for (i = 1; i < nb_patches && !pending; i++) {
    s = cur_state(i);
    if (s && s != ref_state[i])
      pending = true;
    else if (note_mode[i]) {
      el = document.getElementById("in_" + i);
      if (note_mode[i] == 1 ? el.value.trim() != "" : el.value != note_base[i])
        pending = true;
    }
  }
  btn.disabled = !pending;
  if (btn2)
    btn2.disabled = !pending;
}

// "Save changes" button: pushes the local edits, i.e. the states differing
// from the reference, the non-empty note additions, and the note editions
// differing from their base; the reference advances on success (failed
// saves keep everything local for a retry). States are last-write-wins and
// additions are append-only, so they cannot conflict; an edition carries
// the hash of its base blob and the server refuses it if the blob changed
// concurrently, reporting "conflict <cid>" lines that turn the concerned
// inputs red (still in edition; "Get updates" re-bases them for revision).
// Note that a state moved back to the reference by hand is simply not sent.
function save_ref() {
  var st = [], nt = [], rp = [], rp_on = [];
  var body = "", nsent = 0, i, s, el, txt;

  if (!branch)
    return;

  for (i = 1; i < nb_patches; i++) {
    s = cur_state(i);
    if (s && s != ref_state[i]) {
      st[i] = s;
      body += cid[i] + " state " + s + "\n";
      nsent++;
    }
    el = document.getElementById("in_" + i);
    txt = el ? el.value.replace(/\r/g, "").replace(/[\x00-\x1f\x7f]/g, " ").trim() : "";
    if (note_mode[i] == 2) {
      // whole-blob replacement, possibly empty (deletion); only sent when
      // it differs from the base it was computed from
      if (txt != note_base[i]) {
        rp[i] = txt;
        rp_on[i] = 1;
        body += cid[i] + " setnotes " + sdbm(note_base[i]) + " " + txt + "\n";
        nsent++;
      }
    }
    else if (txt) {
      nt[i] = txt;
      body += cid[i] + " notes " + txt + "\n";
      nsent++;
    }
  }

  if (!body) {
    sync_msg("nothing to save");
    return;
  }

  sync_msg("saving...");
  fetch(cgi_url + "?branch=" + branch, { method: "POST", body: body })
    .then(function(r) { if (!r.ok) throw 0; return r.text(); })
    .then(function(t) {
      var confl = {};
      var resp = t.split("\n");
      var i, j, ok = null, warn = "", nbc = 0;

      // The lines of interest may be surrounded by unrelated output (some
      // servers leak the CGI's stderr into the response), so scan for them
      // anywhere: the count ("OK <n> ..."), the conflicts and the warnings.
      for (j = 0; j < resp.length; j++) {
        if (resp[j].indexOf("conflict ") == 0) {
          i = find_line(resp[j].slice(9).trim());
          if (i && !confl[i]) {
            confl[i] = 1;
            nbc++;
          }
        }
        else if (!ok)
          ok = resp[j].match(/^OK (\d+) /);
        if (resp[j].indexOf("warning: ") == 0)
          warn = "; " + resp[j];
      }

      // The server states how many directives it applied: anything neither
      // applied nor reported as a conflict was silently ignored (e.g. an
      // outdated update.bin not knowing a directive). In that case believe
      // the server, not ourselves: advance nothing, keep every edit local
      // for a retry, and say what happened.
      if (!ok || parseInt(ok[1], 10) != nsent - nbc) {
        for (i = 1; i < nb_patches; i++) {
          if (confl[i])
            mark_conflict(i, 1);
        }
        console.log("unexpected update.cgi response: " + t);
        sync_msg("server applied only " + (ok ? ok[1] : "?") + " of " + nsent +
                 " changes (outdated update.cgi/update.bin?), edits kept" + warn);
        return;
      }

      for (i = 1; i < nb_patches; i++) {
        if (st[i])
          ref_state[i] = st[i];
        if (nt[i]) {
          // mirror the server-side coalescing so the display is right
          // without refetching; the next fetch trues it up anyway
          ref_notes[i] = ref_notes[i] ? ref_notes[i] + "; " + nt[i] : nt[i];
          show_notes(i);
          cancel_note(i);
        }
        else if (rp_on[i]) {
          if (confl[i]) {
            // replacement refused, the blob changed server-side: stay in
            // edition and flag it, "Get updates" re-bases it for revision
            mark_conflict(i, 1);
          }
          else {
            ref_notes[i] = rp[i];
            show_notes(i);
            cancel_note(i);
          }
        }
      }
      sync_msg((nbc ? "saved, but " + nbc + " note conflict(s): use Get updates and revise the red one(s)" : "saved") + warn);
      updt_save_btn();
    })
    .catch(function() { sync_msg("save failed (busy?), edits kept"); });
}

// first line to review
var review = 0;

// show/hide table lines and update their color
function updt_table(line) {
  var b = document.getElementById("sh_b").checked;
  var n = document.getElementById("sh_n").checked;
  var u = document.getElementById("sh_u").checked;
  var w = document.getElementById("sh_w").checked;
  var y = document.getElementById("sh_y").checked;
  var tn = 0, tu = 0, tw = 0, ty = 0;
  var bn = 0, bu = 0, bw = 0, by = 0;
  var i, el;

  for (i = 1; i < nb_patches; i++) {
    if (document.getElementById("bt_" + i + "_n").checked) {
      tn++;
      if (bkp[i])
         bn++;
      if (line && i != line)
        continue;
      el = document.getElementById("tr_" + i);
      el.style.backgroundColor = "$BG_N";
      el.style.display = n && (b || !bkp[i]) && i >= review ? "" : "none";
    }
    else if (document.getElementById("bt_" + i + "_u").checked) {
      tu++;
      if (bkp[i])
         bu++;
      if (line && i != line)
        continue;
      el = document.getElementById("tr_" + i);
      el.style.backgroundColor = "$BG_U";
      el.style.display = u && (b || !bkp[i]) && i >= review ? "" : "none";
    }
    else if (document.getElementById("bt_" + i + "_w").checked) {
      tw++;
      if (bkp[i])
         bw++;
      if (line && i != line)
        continue;
      el = document.getElementById("tr_" + i);
      el.style.backgroundColor = "$BG_W";
      el.style.display = w && (b || !bkp[i]) && i >= review ? "" : "none";
    }
    else if (document.getElementById("bt_" + i + "_y").checked) {
      ty++;
      if (bkp[i])
         by++;
      if (line && i != line)
        continue;
      el = document.getElementById("tr_" + i);
      el.style.backgroundColor = "$BG_Y";
      el.style.display = y && (b || !bkp[i]) && i >= review ? "" : "none";
    }
    else {
      // bug
      if (line && i != line)
        continue;
      el = document.getElementById("tr_" + i);
      el.style.backgroundColor = "red";
      el.style.display = "";
    }
  }
  document.getElementById("cnt_n").innerText = tn;
  document.getElementById("cnt_u").innerText = tu;
  document.getElementById("cnt_w").innerText = tw;
  document.getElementById("cnt_y").innerText = ty;

  document.getElementById("cnt_bn").innerText = bn;
  document.getElementById("cnt_bu").innerText = bu;
  document.getElementById("cnt_bw").innerText = bw;
  document.getElementById("cnt_by").innerText = by;
  document.getElementById("cnt_bt").innerText = bn + bu + bw + by;

  document.getElementById("cnt_nbn").innerText = tn - bn;
  document.getElementById("cnt_nbu").innerText = tu - bu;
  document.getElementById("cnt_nbw").innerText = tw - bw;
  document.getElementById("cnt_nby").innerText = ty - by;
  document.getElementById("cnt_nbt").innerText = tn - bn + tu - bu + tw - bw + ty - by;
}

function updt_output() {
  var b = document.getElementById("sh_b").checked;
  var i, y = "", w = "", u = "", n = "";

  for (i = 1; i < nb_patches; i++) {
    if (i < review)
       continue;
    if (bkp[i])
       continue;
    if (document.getElementById("bt_" + i + "_y").checked)
       y = y + " " + cid[i];
    else if (document.getElementById("bt_" + i + "_w").checked)
       w = w + " " + cid[i];
    else if (document.getElementById("bt_" + i + "_u").checked)
       u = u + " " + cid[i];
    else if (document.getElementById("bt_" + i + "_n").checked)
       n = n + " " + cid[i];
  }

  // update the textarea
  document.getElementById("output").value =
    "cid_y=(" + y + " )\n" +
    "cid_w=(" + w + " )\n" +
    "cid_u=(" + u + " )\n" +
    "cid_n=(" + n + " )\n";
}

function updt(line,value) {
  if (value == "r") {
    review = line;
    line = 0; // redraw everything
  }
  updt_table(line);
  updt_output();
  updt_save_btn();
}

function show_only(b,n,u,w,y) {
    document.getElementById("sh_b").checked = !!b;
    document.getElementById("sh_n").checked = !!n;
    document.getElementById("sh_u").checked = !!u;
    document.getElementById("sh_w").checked = !!w;
    document.getElementById("sh_y").checked = !!y;
    document.getElementById("show_all").checked = true;
    updt(0,"r");
}

// Resynchronizes the review variable with the checked review radio: across
// a reload, the browser restores the radios to the user's last selection
// (e.g. "All") while the variable is regenerated to the default first line
// to review, and the listing would not match the checked radio anymore.
function init_review() {
  var i, el;

  if (document.getElementById("show_all").checked) {
    review = 0;
    return;
  }
  for (i = 1; i <= nb_patches; i++) {
    el = document.getElementById("rv_" + i);
    if (el && el.checked) {
      review = i;
      return;
    }
  }
}

// -->
</script>
</HEAD>
EOF

echo "<BODY>"

# the syncing UI is only emitted when the branch is known; the page reaches
# update.cgi with a bare relative URL so it must sit in the same directory.
if [ -n "$VERSION" ]; then
	echo -n "<div style='float: right; text-align: right;'>"
	echo -n "<button onclick='fetch_ref();' title='Retrieve the latest shared review state'>Get updates</button> "
	echo -n "<button id='save_btn' disabled onclick='save_ref();' title='Push your local edits to the shared state'>Save changes</button>"
	echo "<br/><small id='sync_msg'></small></div>"
fi

echo -n "<table cellpadding=3 cellspacing=5 style='font-size: 150%;'><tr><th align=left>Backported</th>"
echo -n "<td style='background-color:$BG_N'><a href='#' onclick='show_only(1,1,0,0,0);'> N: <span id='cnt_bn'>0</span> </a></td>"
echo -n "<td style='background-color:$BG_U'><a href='#' onclick='show_only(1,0,1,0,0);'> U: <span id='cnt_bu'>0</span> </a></td>"
echo -n "<td style='background-color:$BG_W'><a href='#' onclick='show_only(1,0,0,1,0);'> W: <span id='cnt_bw'>0</span> </a></td>"
echo -n "<td style='background-color:$BG_Y'><a href='#' onclick='show_only(1,0,0,0,1);'> Y: <span id='cnt_by'>0</span> </a></td>"
echo -n "<td>total: <span id='cnt_bt'>0</span></td>"
echo "</tr><tr>"
echo -n "<th align=left>Not backported</th>"
echo -n "<td style='background-color:$BG_N'><a href='#' onclick='show_only(0,1,0,0,0);'> N: <span id='cnt_nbn'>0</span> </a></td>"
echo -n "<td style='background-color:$BG_U'><a href='#' onclick='show_only(0,0,1,0,0);'> U: <span id='cnt_nbu'>0</span> </a></td>"
echo -n "<td style='background-color:$BG_W'><a href='#' onclick='show_only(0,0,0,1,0);'> W: <span id='cnt_nbw'>0</span> </a></td>"
echo -n "<td style='background-color:$BG_Y'><a href='#' onclick='show_only(0,0,0,0,1);'> Y: <span id='cnt_nby'>0</span> </a></td>"
echo -n "<td>total: <span id='cnt_nbt'>0</span></td>"
echo "</tr></table><P/>"
echo -n "<big><big>Show:"
echo -n " <span style='background-color:$BG_B'><input type='checkbox' onclick='updt_table(0);' id='sh_b' checked />B (${#bkp[*]})</span> "
echo -n " <span style='background-color:$BG_N'><input type='checkbox' onclick='updt_table(0);' id='sh_n' checked />N (<span id='cnt_n'>0</span>)</span> "
echo -n " <span style='background-color:$BG_U'><input type='checkbox' onclick='updt_table(0);' id='sh_u' checked />U (<span id='cnt_u'>0</span>)</span> "
echo -n " <span style='background-color:$BG_W'><input type='checkbox' onclick='updt_table(0);' id='sh_w' checked />W (<span id='cnt_w'>0</span>)</span> "
echo -n " <span style='background-color:$BG_Y'><input type='checkbox' onclick='updt_table(0);' id='sh_y' checked />Y (<span id='cnt_y'>0</span>)</span> "
echo -n "</big/></big><br/>(B=show backported, N=no/drop, U=uncertain, W=wait/next, Y=yes/pick"
echo ")<P/>"

echo "<TABLE COLS=5 BORDER=1 CELLSPACING=0 CELLPADDING=3>"
echo "<TR><TH>All<br/><input type='radio' name='review' id='show_all' onclick='updt(0,\"r\");' checked title='Start review here'/></TH><TH>CID</TH><TH>Subject</TH><TH>Verdict<BR>N U W Y</BR></TH><TH>Reason</TH></TR>"
seq_num=1; do_check=1; review=0;
for patch in "${PATCHES[@]}"; do
        # try to retrieve the patch's numbering (0001-9999)
        pnum="${patch##*/}"
        pnum="${pnum%%[^0-9]*}"

        id=$(sed -ne 's/^#id: \(.*\)/\1/p' "$patch")
        resp=$(grep -v ^llama "$patch" | sed -ne '/^Explanation:/,$p' | sed -z 's/\n[\n]*/\n/g' | sed -z 's/\([^. ]\)\n\([A-Z]\)/\1.\n\2/' | tr '\012' ' ')
        resp="${resp#Explanation:}";
        while [ -n "$resp" -a -z "${resp##[ .]*}" ]; do
                resp="${resp#[ .]}"
        done

        respl=$(echo -- "$resp" | tr 'A-Z' 'a-z')

        if [[ "${respl}" =~ (conclusion|verdict)[:\ ][^.]*yes ]]; then
                verdict=yes
        elif [[ "${respl}" =~ (conclusion|verdict)[:\ ][^.]*wait ]]; then
                verdict=wait
        elif [[ "${respl}" =~ (conclusion|verdict)[:\ ][^.]*no ]]; then
                verdict=no
        elif [[ "${respl}" =~ (conclusion|verdict)[:\ ][^.]*uncertain ]]; then
                verdict=uncertain
        elif [[ "${respl}" =~ (\"wait\"|\"yes\"|\"no\"|\"uncertain\")[^\"]*$ ]]; then
                # last word under quotes in the response, sometimes happens as
                # in 'thus I would conclude "no"'.
                verdict=${BASH_REMATCH[1]}
        else
                verdict=uncertain
        fi

        verdict="${verdict//[\"\',;:. ]}"
        verdict=$(echo -n "$verdict" | tr '[A-Z]' '[a-z]')

        # There are two formats for the ID line:
        #   - old: #id: cid subject
        #   - new: #id: cid author date subject
        # We can detect the 2nd one as the date starts with a series of digits
        # followed by "-" then an upper case letter (eg: "18-Dec23").
        set -- $id
        cid="$1"
        author=""
        date=""
        if [ -n "$3" ] && [ -z "${3##[1-9]-[A-Z]*}" -o -z "${3##[0-3][0-9]-[A-Z]*}" ]; then
            author="$2"
            date="$3"
            subj="${id#$cid $author $date }"
        else
            subj="${id#$cid }"
        fi

        if [ -z "$cid" ]; then
            echo "ERROR: commit ID not found in patch $pnum: $patch" >&2
            continue
        fi

        echo "<script type='text/javascript'>cid[$seq_num]='$cid'; bkp[$seq_num]=${bkp[$cid]:+1}+0;</script>"

        echo -n "<TR id='tr_$seq_num' name='$cid'"

        # highlight unqualified docs and bugs
        if [ "$verdict" != "no" ]; then
                : # no special treatment for accepted/uncertain elements
        elif [ -z "${subj##BUG*}" ] && ! [[ "${respl}" =~ (explicitly|specifically|clearly|also|commit\ message|does)[\ ]*(state|mention|say|request) ]]; then
                # bold for BUG marked "no" with no "explicitly states that ..."
                echo -n " style='font-weight:bold'"
        elif [ -z "${subj##DOC*}" ]; then # && ! [[ "${respl}" =~ (explicitly|specifically|clearly|also|commit\ message|does)[\ ]*(state|mention|say|request) ]]; then
                # gray for DOC marked "no"
                echo -n " style='font-weight:bold'"
                #echo -n " bgcolor=#E0E0E0" #"$BG_U"
        fi

        echo -n ">"

        # HTMLify subject and summary
        subj="${subj//&/&amp;}"; subj="${subj//</&lt;}"; subj="${subj//>/&gt;}";
        resp="${resp//&/&amp;}"; resp="${resp//</&lt;}"; resp="${resp//>/&gt;}";

        # turn "#XXXX" to a link to an issue
        resp=$(echo "$resp" | sed -e "s|#\([0-9]\{1,5\}\)|<a href='${ISSUES}\1'>#\1</a>|g")

        # put links to commit IDs
        resp=$(echo "$resp" | sed -e "s|\([0-9a-f]\{7,40\}\)|<a href='${GITURL}\1'>\1</a>|g")

        echo -n "<TD nowrap align=center ${bkp[$cid]:+style='background-color:${BG_B}'}>$seq_num<BR/>"
        echo -n "<input type='radio' name='review' id='rv_$seq_num' onclick='updt($seq_num,\"r\");' ${do_check:+checked} title='Start review here'/></TD>"
        # only the first 8 chars of the commit id are displayed (enough to be
        # unambiguous on one page); everything keyed (href, name=, cid[])
        # carries the full id produced by the pipeline, whatever its length.
        echo -n "<TD nowrap ${bkp[$cid]:+style='background-color:${BG_B}'}><tt><a href='${GITURL}${cid}'>${cid:0:8}</a></tt>${date:+<br/><small style='font-weight:normal'>$date</small>}</TD>"
        echo -n "<TD nowrap><a href='${GITURL}${cid}'>${pnum:+$pnum }$subj</a>${author:+<br/><div align=right><small style='font-weight:normal'>$author</small></div>}</TD>"
        echo -n "<TD nowrap align=center>"
        echo -n "<input type='radio' onclick='updt($seq_num,\"n\");' id='bt_${seq_num}_n' class='n' name='$cid' value='n' title='Drop' $(         [ "$verdict" != no ]     || echo -n checked) />"
        echo -n "<input type='radio' onclick='updt($seq_num,\"u\");' id='bt_${seq_num}_u' class='u' name='$cid' value='u' title='Uncertain' $(    [ "$verdict" != uncertain ] || echo -n checked) />"
        echo -n "<input type='radio' onclick='updt($seq_num,\"w\");' id='bt_${seq_num}_w' class='w' name='$cid' value='w' title='wait in -next' $([ "$verdict" != wait ]   || echo -n checked) />"
        echo -n "<input type='radio' onclick='updt($seq_num,\"y\");' id='bt_${seq_num}_y' class='y' name='$cid' value='y' title='Pick' $(         [ "$verdict" != yes ]    || echo -n checked) />"
        echo -n "</TD>"

        # the div is the dedicated container for the shared reviewers' notes,
        # filled by full replacement (never appended to) by the JS; the
        # hidden input receives the user's own note to be pushed on save
        echo -n "<TD>$resp<div class='notes' id='notes_$seq_num'></div>"
        if [ -n "$VERSION" ]; then
            echo -n "<a href='#' onclick='add_note($seq_num); return false;' id='ln_add_$seq_num' title='Add a shared note to this commit'><small>[add note]</small></a>"
            echo -n " <a href='#' onclick='edit_note($seq_num); return false;' id='ln_edit_$seq_num' style='display:none' title='Edit or delete the whole note'><small>[edit note]</small></a>"
            echo -n " <a href='#' onclick='cancel_note($seq_num); return false;' id='ln_cancel_$seq_num' style='display:none' title='Abort this note edition'><small>[cancel]</small></a>"
            echo -n " <input type='text' id='in_$seq_num' maxlength='500' size='80' style='display:none' oninput='updt_save_btn();' />"
        fi
        echo -n "</TD>"
        echo "</TR>"
        echo
        ((seq_num++))

        # if this patch was already backported, make the review start on the next
        if [ -n "${bkp[$cid]}" ]; then
            review=$seq_num
            do_check=1
        else
            do_check=
        fi
done

echo "<TR><TH>New<br/><input type='radio' name='review' id='rv_$seq_num' onclick='updt($seq_num,\"r\");' ${do_check:+checked} title='Nothing to backport'/></TH><TH>CID</TH><TH>Subject</TH><TH>Verdict<BR>N U W Y</BR></TH><TH>Reason</TH></TR>"

echo "</TABLE>"

# a copy of the syncing buttons at the bottom right: that's where the user
# ends up after a review, far from the top ones, and forgetting to save the
# work is too easy when no button remains in sight
if [ -n "$VERSION" ]; then
	echo -n "<div style='float: right; text-align: right;'>"
	echo -n "<button onclick='fetch_ref();' title='Retrieve the latest shared review state'>Get updates</button> "
	echo -n "<button id='save_btn2' disabled onclick='save_ref();' title='Push your local edits to the shared state'>Save changes</button>"
	echo "<br/><small id='sync_msg2'></small></div>"
fi

echo "<P/>"
echo "<H3>Output:</H3>"
echo "<textarea cols=120 rows=10 id='output'></textarea>"
echo "<P/>"
echo "<script type='text/javascript'>nb_patches=$seq_num; review=$review; init_review(); init_ref(); updt_table(0); updt_output();</script>"
echo "</BODY></HTML>"
