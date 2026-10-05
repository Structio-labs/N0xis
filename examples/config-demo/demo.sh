#!/usr/bin/env bash
# demo.sh: the scripted session behind docs/assets/live-loop.gif.
#
# Every command shown is the command that runs: the "typing" is only how it is
# printed. Run it yourself:
#
#   cc -O2 -g -o config_demo config_demo.c
#   N0X=/path/to/n0xis ./demo.sh        # N0X defaults to `n0x` on PATH
#
# Linux, x86-64, needs jq. The demo program allows itself to be traced (see
# config_demo.c), so no ptrace_scope change is needed.
set -u
cd "$(dirname "$0")"
N0X_BIN="${N0X:-n0x}"
n0x() { "$N0X_BIN" "$@"; }

# Keep scan results out of the user's own n0x project.
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

[ -x ./config_demo ] || cc -O2 -g -o config_demo config_demo.c

clear
say "a running program keeps its settings encrypted; the plaintext exists only in its memory"
printf '%s$%s ./config_demo &\n' "$GREEN" "$RESET"
./config_demo & PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null; rm -f found.json' EXIT
sleep 1.4

say "1. find the decrypted settings in memory: they start with \"server=\""
type_and_run "n0x scan aob --pid $PID --pattern '73 65 72 76 65 72 3d' --quiet | tee found.json | jq -c .data.matches"
ADDR=$(jq -r '.data.matches[0]' found.json)   # read back what the command above printed

say "2. watch that address with a hardware watchpoint; the program reloads its settings in 5 s"
type_and_run "(sleep 5; kill -USR1 $PID) &"
type_and_run "n0x provenance trace --pid $PID --addr $ADDR --quiet | jq -r '.data.entries[0].decompiled_context[1:6][]'"

say "the loop that decrypted it: each byte XOR-ed with a key that changes as it goes (key * 13 + 7)"
sleep 3
