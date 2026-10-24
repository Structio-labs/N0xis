#!/bin/sh
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# The whole rule-accuracy run: build the corpus, measure every variant, sum the
# tables, show the bytes behind every wrong answer, calibrate the instrument.
# Scratch goes to $RULE_ACCURACY_SCRATCH (default ~/.cache/rule-accuracy); the
# engine measured is $N0XIS (default ~/.local/opt/n0xis-wasm-preview/n0xis).
#
#   sh oracle/rule-accuracy/run_all.sh                 # everything
#   sh oracle/rule-accuracy/run_all.sh --only x86_64/lua   # a subset (ids contain it)
#
# Two compiles at a time at most; every compile and every engine call is under
# `timeout`. Run it inside a memory cap on a small machine (README).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
scratch=${RULE_ACCURACY_SCRATCH:-$HOME/.cache/rule-accuracy}
mkdir -p "$scratch/results"
python3 "$here/build.py" "$@" --jobs 2 | tee "$scratch/build.log"
python3 "$here/run.py" "$@" | tee "$scratch/run.log"
python3 "$here/report.py"
python3 "$here/evidence.py" > "$scratch/results/evidence.txt"
# Calibrated on three configurations of three machines, not one: a check
# shown to work on one input is shown to work on that input.
: > "$scratch/results/calibration.txt"
for cfg in x86_64/lua/gcc-O2 i686/zstd/clang-Os aarch64/lua/gcc-O2; do
    if [ -f "$scratch/results/$cfg/c.summary.json" ]; then
        python3 "$here/calibrate.py" "$cfg" >> "$scratch/results/calibration.txt"
    else
        echo "calibration: $cfg was not measured in this run; not calibrated on it" | tee -a "$scratch/results/calibration.txt" >&2
    fi
done
python3 "$here/calibrate.py" --truth-all > "$scratch/results/truth-crosscheck.txt"
grep -h 'calibration:' "$scratch/results/calibration.txt" "$scratch/results/truth-crosscheck.txt"
