#!/bin/bash

SCRIPTS_DIR="$HOME/prog/scripts"
HAPROXY_DIR="$HOME/data/in/haproxy"
PATCHES_PFX="$HOME/data/in/patches"
VERDICT_DIR="$HOME/data/out"
PROMPTS_DIR="$HOME/data/prompts"
MODELS_DIR="$HOME/data/models"
MAINPROG="$HOME/prog/bin/main"

PARALLEL_RUNS=2

BRANCH=$(cd "$HAPROXY_DIR" && git describe --tags HEAD|cut -f1 -d-|cut -f2- -dv)
if [ -z "$BRANCH" ]; then
	echo "Couldn't guess current branch, aborting."
	exit 1
fi

# eg: for v3.0-dev0^ we should get v2.9.0 hence "2.9"
STABLE=$(cd "$HAPROXY_DIR" && git describe --tags "v${BRANCH}-dev0^" |cut -f1,2 -d.|cut -f2- -dv)

PATCHES_DIR="$PATCHES_PFX"-"$BRANCH"

(cd "$HAPROXY_DIR"
 git pull
 last_file=$(ls -1 "$PATCHES_DIR"/*.patch 2>/dev/null | tail -n1)
 if [ -n "$last_file" ]; then
	restart=$(head -n1 "$last_file" | cut -f2 -d' ')
 else
	restart="v${BRANCH}-dev0"
 fi
 "$SCRIPTS_DIR"/mk-patch-list.sh -o "$PATCHES_DIR" -b v${BRANCH}-dev0 $(git log $restart.. --oneline | cut -f1 -d' ')
)

# List backported fixes (possibly none)
BKP=(
    $(
        cd "$HAPROXY_DIR"
        if ! git remote update "$STABLE"; then
            git remote add "$STABLE" "http://git.haproxy.org/git/haproxy-${STABLE}.git/"
            git remote update "$STABLE"
        fi >&2

        git log --no-decorate --reverse "v${STABLE}.0..${STABLE}/master" |
            sed -ne 's,(cherry picked from commit \(.\{8\}\).*,\1,p'
    )
)

# by far the best model for now with little uncertain and few wait
echo "${BRANCH}: mistral-7b-v0.2"

if [ ! -e "${PROMPTS_DIR}/prompt-${BRANCH}-m7bv02.cache" -o "${PROMPTS_DIR}/prompt15-${BRANCH}-mist7bv2-pfx.txt" -nt "${PROMPTS_DIR}/prompt-${BRANCH}-m7bv02.cache" ]; then
    echo "Regenerating the prompt cache, may take 1-2 min"
    rm -f "${PROMPTS_DIR}/prompt-${BRANCH}-m7bv02.cache"
    rm -f empty
    touch empty
    time EXT=m7bv02.txt MODEL=${MODELS_DIR}/mistral-7b-instruct-v0.2.Q5_K_M.gguf CACHE=${PROMPTS_DIR}/prompt-${BRANCH}-m7bv02.cache CACHE_RO= PROMPT_PFX=${PROMPTS_DIR}/prompt15-${BRANCH}-mist7bv2-pfx.txt PROMPT_SFX=${PROMPTS_DIR}/prompt15-${BRANCH}-mist7bv2-sfx.txt MAINPROG=$MAINPROG PROGRAM="$SCRIPTS_DIR"/process-patch-v15.sh "$SCRIPTS_DIR"/submit-ai.sh empty
    rm -f empty empty.m7bv02.txt
    echo "Done!"
fi

# Now process the patches, may take 1-2 hours
time EXT=m7bv02.txt MODEL=${MODELS_DIR}/mistral-7b-instruct-v0.2.Q5_K_M.gguf CACHE=${PROMPTS_DIR}/prompt-${BRANCH}-m7bv02.cache PROMPT_PFX=${PROMPTS_DIR}/prompt15-${BRANCH}-mist7bv2-pfx.txt PROMPT_SFX=${PROMPTS_DIR}/prompt15-${BRANCH}-mist7bv2-sfx.txt MAINPROG=$MAINPROG PROGRAM="$SCRIPTS_DIR"/process-patch-v15.sh "$SCRIPTS_DIR"/submit-ai.sh -s ${PARALLEL_RUNS} ${PATCHES_DIR}/*.patch

# generate the output, takes 3-5 seconds
"$SCRIPTS_DIR"/post-ai.sh -b "${BKP[*]}" ${PATCHES_DIR}/*.m7bv02.txt > ${VERDICT_DIR}/verdict-${BRANCH}-m7bv02.html
