#!/bin/bash

# the patch itself
F="$1"
shift

# if non-empty, force to redo the patch
FORCE="${FORCE:-}"

CPU="${CPU:-$(nproc)}"
MODEL="${MODEL:-../models/airoboros-l2-13b-gpt4-1.4.1.Q5_K_M.gguf}"
PROMPT_PFX="${PROMPT_PFX:-prompt14-airo14-pfx.txt}"
PROMPT_SFX="${PROMPT_SFX:-prompt14-airo14-sfx.txt}"
CACHE="${CACHE:-prompt-airo14.cache}"
CACHE_RO="${CACHE_RO- --prompt-cache-ro}"
EXT="${EXT:-airo14.txt}"
OUTPUT="${OUTPUT:-$(set -- "$F"."$EXT"; echo $1)}"
MAINPROG="${MAINPROG:-./main}"

# switch to interactive mode with this reverse-prompt at the end if set.
# Typically: INTERACTIVE="Developer".
INTERACTIVE=${INTERACTIVE:-""}

# Compute the full prompt
#
# Input format for "$F": git-format-patch with lines in this order:
#   1: From cid ...
#   2: From: author user@...
#   3: Date:
#   4: Subject:
#   ...
#   n: ^---$
# It will emit a preliminary line with the commit ID, the author, the date,
# the subject, then the whole commit message indented. The output can be
# searched using grep '^\(Bot:\|#id:\)'

PROMPT="$(cat "$PROMPT_PFX"; cat "$F" | sed -e '/^---/,$d'  -e '/^Signed-off-by:/d' -e '/^Cc:/d' -e '/^Reported-by:/d' -e '/^Acked-by:/d' -e '1s/From \([0-9a-f]\{8\}\)\([0-9a-f]\{32\}\).*/\1/'  -e '2s/^From: .*<\([^<@>]*\)@\([^<.>]*\).*/\1@\2/' -e '3s/^Date:[^,]*, \([^ ]*\) \([^ ]*\) 20\([^ ]*\).*/\1-\2\3/' | sed -ne '1h;1d;2x;2G;2h;2d;3x;3G;3h;3d;4x;4G;4s/^\([^\n]*\)\n\([^\n]*\)\n\([^\n]*\)\nSubject: \(.*\)/#id: \1 \2 \3 \4\n\nSubject: \4/;p' | sed -e '3,$s/^/    \0/'; echo; cat "$PROMPT_SFX")"

# already done: don't do it again. Note that /dev/null is OK
if [ -z "$FORCE" -a -s "$OUTPUT" ]; then
        exit 0
fi

# In order to rebuild the prompt cache:
#   OUTPUT=blah CACHE_RO= ./$0 /dev/null
#
# Note: airoboros is able to carefully isolate an entire context, tests show
# that it's possible to ask it to repeat the entire commit message and it does
# so correctly. However its logic is sometimes bizarre


if [ -z "$INTERACTIVE" ]; then
        LANG=C "$MAINPROG" --log-disable --model "$MODEL" --threads "$CPU" --ctx_size 4096 --temp 0.36 --top_k 12 --top_p 1 --repeat_last_n 256 --batch_size 16384 --repeat_penalty 1.1 --n_predict 200 --multiline-input --prompt "$PROMPT" --prompt-cache "$CACHE" $CACHE_RO "$@" 2>&1 | grep -v ^llama_model_loader | grep -v ^llm_load_ > "${OUTPUT}"
	if [ "$?" != 0 ]; then
		# failed: this is likely because the text is too long
		(echo "$PROMPT"; echo
		 echo "Explanation: the commit message was way too long, couldn't analyse it."
		 echo "Conclusion: uncertain"
		 echo) > "${OUTPUT}"
	fi
else
        LANG=C "$MAINPROG" --log-disable --model "$MODEL" --threads "$CPU" --ctx_size 4096 --temp 0.36 --repeat_penalty 1.1 --n_predict 200 --multiline-input --prompt "$PROMPT" --prompt-cache "$CACHE" $CACHE_RO -n -1 -i --color --in-prefix ' ' --reverse-prompt "$INTERACTIVE:" "$@"
fi
