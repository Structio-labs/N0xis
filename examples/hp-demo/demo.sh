#!/usr/bin/env bash
# demo.sh: the scripted session behind docs/assets/provenance.gif.
#
# Every command shown is the command that runs: the "typing" is only how it is
# printed. Run it yourself:
#
#   cc -O2 -g -o hp_demo hp_demo.c
#   N0X=/path/to/n0xis ./demo.sh        # N0X defaults to `n0x` on PATH
#
# Linux, x86-64. The demo program allows itself to be traced (see hp_demo.c),
# so no ptrace_scope change is needed.
set -u
cd "$(dirname "$0")"
N0X_BIN="${N0X:-n0x}"
n0x() { "$N0X_BIN" "$@"; }

# Keep scan dumps out of the user's own n0x project.
export XDG_DATA_HOME="${XDG_DATA_HOME_DEMO:-$(mktemp -d)}"

GREEN=$'\e[1;32m'; DIM=$'\e[2m'; RESET=$'\e[0m'
say()  { printf '%s# %s%s\n' "$DIM" "$1" "$RESET"; sleep 0.6; }
type_and_run() {
    printf '%s$%s ' "$GREEN" "$RESET"
    local cmd="$1" i
    for ((i = 0; i < ${#cmd}; i++)); do printf '%s' "${cmd:i:1}"; sleep 0.018; done
    printf '\n'
    eval "$cmd"
    sleep 1.1
}

[ -x ./hp_demo ] || cc -O2 -g -o hp_demo hp_demo.c

clear
say "a running program shows a value: hp = 100"
printf '%s$%s ./hp_demo &\n' "$GREEN" "$RESET"
./hp_demo & PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null' EXIT
sleep 1.4

say "1. first scan: every int32 in its memory equal to 100"
type_and_run "n0x scan value --pid $PID --type i32 --value 100 --save-as hp --quiet | jq .data.total_matches"

say "2. take a hit, then keep only what became 99"
type_and_run "kill -USR1 $PID"
type_and_run "n0x scan filter --pid $PID --from hp --criterion exact --value 99 --save-as hp2 --quiet | tee hp2.json | jq -c .data.matches"
ADDR=$(jq -r '.data.matches[0].addr' hp2.json)   # read back what the command above printed

say "3. watch that address; the next hit arrives in 5 s"
type_and_run "(sleep 5; kill -USR1 $PID) &"
type_and_run "n0x provenance trace --pid $PID --addr $ADDR --quiet | jq -r '.data.entries[0].decompiled_context[1]'"

say "the statement that wrote it: hp -= 1"
sleep 3
