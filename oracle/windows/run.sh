#!/usr/bin/env bash
# run.sh: build the Windows binaries and the live target here, run win_check.py
# on a Windows machine over SSH, then check that the Windows build and the Linux
# build give the same static answer on the same PE.
#
#   oracle/windows/run.sh                # WIN_HOST defaults to `winlaptop`
#   BUILD=0 oracle/windows/run.sh        # reuse binaries already cross-built
#
# Needs: mingw-w64 (x86_64-w64-mingw32-gcc), ssh/scp access to a Windows host
# with Python 3 on PATH. Build heavy Rust inside a memory cap on small machines.
set -uo pipefail
HOST="${WIN_HOST:-winlaptop}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
W="$ROOT/target/x86_64-pc-windows-gnu/release"
L="$ROOT/target/release/n0xis"

if [ "${BUILD:-1}" = 1 ]; then
    RUSTUP_TOOLCHAIN=stable-x86_64-unknown-linux-gnu cargo build --release \
        --manifest-path "$ROOT/Cargo.toml" --target x86_64-pc-windows-gnu -p n0xis-cli -p n0xis-mcp || exit 1
    cargo build --release --manifest-path "$ROOT/Cargo.toml" -p n0xis-cli || exit 1
fi
x86_64-w64-mingw32-gcc -O2 -o "$W/wtarget.exe" "$ROOT/oracle/windows/wtarget.c" || exit 1

ssh "$HOST" 'New-Item -ItemType Directory -Force -Path C:\n0xtest | Out-Null' || exit 1
scp -q "$W/n0xis.exe" "$W/n0xis-mcp.exe" "$W/wtarget.exe" "$ROOT/oracle/windows/win_check.py" \
    "$HOST:C:/n0xtest/" || exit 1

ssh "$HOST" '[Console]::OutputEncoding=[Text.Encoding]::UTF8; python C:\n0xtest\win_check.py --dir C:\n0xtest'
fails=$?

# Same PE, two builds: the static answer must not depend on the host OS.
tmp="$(mktemp -d)"
scp -q "$HOST:C:/n0xtest/win_check_report.json" "$tmp/report.json" || exit 1
pe_win="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pe"])' "$tmp/report.json")"
scp -q "$HOST:${pe_win//\\//}" "$tmp/pe.dll" || exit 1
python3 -B - "$tmp/report.json" "$tmp/pe.dll" "$L" "$ROOT/oracle/windows/win_check.py" <<'PY'
import hashlib, importlib.util, json, subprocess, sys
report, pe, n0x, wc_path = sys.argv[1:]
spec = importlib.util.spec_from_file_location("wc", wc_path)
wc = importlib.util.module_from_spec(spec); spec.loader.exec_module(wc)
base, _ = wc.pdata_entries(pe)
out = subprocess.run([n0x, "function", "discover", "--file", pe, "--pdata", "--limit", "0", "--quiet"],
                     capture_output=True).stdout
found = sorted({wc.as_rva(f["va"], base) for f in json.loads(out)["data"]["functions"]})
sha = hashlib.sha256(",".join(f"{x:x}" for x in found).encode()).hexdigest()
r = json.load(open(report))
same = sha == r["discover_starts_sha256"]
print(f"[{'PASS' if same else 'FAIL'}] Linux and Windows builds agree on the same PE: "
      f"{len(found)} vs {r['discover_count']} functions")
sys.exit(0 if same else 1)
PY
parity=$?
echo "windows checks failed: $fails, cross-build parity failed: $parity"
exit $(( fails + parity ))
