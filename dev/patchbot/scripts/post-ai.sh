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

USAGE="Usage: ${0##*/} [ -h ] [ -b 'bkp_list' ] patch..."
MYSELF="$0"
GITURL="http://git.haproxy.org/?p=haproxy.git;a=commitdiff;h="
ISSUES="https://github.com/haproxy/haproxy/issues/"
BKP=""

while [ -n "$1" -a -z "${1##-*}" ]; do
	case "$1" in
		-h|--help) quit "$USAGE" ;;
		-b)        BKP="$2"; shift 2 ;;
		*)         die  "$USAGE" ;;
	esac
done

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
</style>

<script type="text/javascript"><!--

var nb_patches = 0;
var cid = [];
var bkp = [];

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

// -->
</script>
</HEAD>
EOF

echo "<BODY>"
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
        echo -n "<input type='radio' name='review' onclick='updt($seq_num,\"r\");' ${do_check:+checked} title='Start review here'/></TD>"
        echo -n "<TD nowrap ${bkp[$cid]:+style='background-color:${BG_B}'}><tt><a href='${GITURL}${cid}'>$cid</a></tt>${date:+<br/><small style='font-weight:normal'>$date</small>}</TD>"
        echo -n "<TD nowrap><a href='${GITURL}${cid}'>${pnum:+$pnum }$subj</a>${author:+<br/><div align=right><small style='font-weight:normal'>$author</small></div>}</TD>"
        echo -n "<TD nowrap align=center>"
        echo -n "<input type='radio' onclick='updt($seq_num,\"n\");' id='bt_${seq_num}_n' class='n' name='$cid' value='n' title='Drop' $(         [ "$verdict" != no ]     || echo -n checked) />"
        echo -n "<input type='radio' onclick='updt($seq_num,\"u\");' id='bt_${seq_num}_u' class='u' name='$cid' value='u' title='Uncertain' $(    [ "$verdict" != uncertain ] || echo -n checked) />"
        echo -n "<input type='radio' onclick='updt($seq_num,\"w\");' id='bt_${seq_num}_w' class='w' name='$cid' value='w' title='wait in -next' $([ "$verdict" != wait ]   || echo -n checked) />"
        echo -n "<input type='radio' onclick='updt($seq_num,\"y\");' id='bt_${seq_num}_y' class='y' name='$cid' value='y' title='Pick' $(         [ "$verdict" != yes ]    || echo -n checked) />"
        echo -n "</TD>"
        echo -n "<TD>$resp</TD>"
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

echo "<TR><TH>New<br/><input type='radio' name='review' onclick='updt($seq_num,\"r\");' ${do_check:+checked} title='Nothing to backport'/></TH><TH>CID</TH><TH>Subject</TH><TH>Verdict<BR>N U W Y</BR></TH><TH>Reason</TH></TR>"

echo "</TABLE>"
echo "<P/>"
echo "<H3>Output:</H3>"
echo "<textarea cols=120 rows=10 id='output'></textarea>"
echo "<P/>"
echo "<script type='text/javascript'>nb_patches=$seq_num; review=$review; updt_table(0); updt_output();</script>"
echo "</BODY></HTML>"
