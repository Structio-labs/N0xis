#!/bin/sh
# Copyright (c) 2026 Tymofii Kosovskyi
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Build, measure, score and report the obfuscation corpus, inside a
# memory-capped scope so a runaway compile cannot take down the desktop (this
# machine has 16 GB and a shared budget). Everything goes under
# ~/.cache/obfuscation (OBF_SCRATCH); nothing is written into the repo.
#
#   sh oracle/obfuscation/run_all.sh                         # everything built so far
#   sh oracle/obfuscation/run_all.sh --only x86_64/calib     # one slice
#   sh oracle/obfuscation/run_all.sh --transform junk        # one transformation
#
# Extra arguments are passed through to obf_run.py (--only, --transform,
# --rescore, --budget). The engine is $N0XIS (default the wasm preview build).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

run() {
    if command -v systemd-run >/dev/null 2>&1 && [ -S "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bus" ]; then
        systemd-run --user --scope -q --expand-environment=no \
            -p MemoryHigh=4G -p MemoryMax=5G --nice=19 -- "$@"
    else
        "$@"
    fi
}

run python3 obf_run.py "$@"
python3 obf_report.py
