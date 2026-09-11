#!/usr/bin/env sh
# Boundary law (CONCEPT §3.2 / §4): the pure crates name only abstractions.
# `n0xis-core` and the seams it depends on must never pull in an OS API, a
# file-format parser, an async runtime, or a frontend framework — that is what
# lets the whole analysis pipeline be tested against the `Snapshot` mock and
# keeps a second OS an *adapter*, not a rewrite.
#
# The law was documented but only ever checked by hand; this script makes it
# mechanical. Run it locally exactly as CI does:
#
#   sh scripts/check_boundary.sh
#
# Exit 0 = boundary holds, exit 1 = a forbidden crate reached a pure crate.
set -eu

# Crates that must stay pure. Everything the analysis brain sits on.
# Overridable so the check itself can be exercised, e.g.
# `PURE_CRATES=n0xis-project sh scripts/check_boundary.sh` must FAIL
# (n0xis-project legitimately pulls windows-sys via `dirs` — it owns `.n0x/`
# on disk and is not a pure crate).
PURE_CRATES="${PURE_CRATES:-n0xis-contracts n0xis-arch n0xis-core}"

# Forbidden transitive dependencies, by reason:
#   windows-sys / windows-targets — OS APIs (the `live` adapter's business)
#   goblin, png                   — file/image format parsers (source adapters)
#   libloading                    — dynamic loading (n0xis-hud only)
#   eframe, winit                 — GUI frontend
#   tokio, rmcp, clap             — frontend/transport concerns
#   n0xis-frontend                — the frontend seam; the arrow points down
#                                   only (frontends depend on the core, never
#                                   the reverse), and this is what keeps it so
#   n0xis-il2cpp                  — the IL2CPP managed layer (Phase 12). A
#                                   format parser for `global-metadata.dat` and
#                                   external dumps; same adapter rule, listed
#                                   the day the crate landed.
# One regex, anchored, matched against bare package names.
FORBIDDEN='^(windows-sys|windows-targets|goblin|png|libloading|eframe|winit|tokio|rmcp|clap|n0xis-frontend|n0xis-il2cpp)$'

status=0

for crate in $PURE_CRATES; do
  # `--edges normal` drops dev/build deps: a test-only or proc-macro dependency
  # is not linked into the crate and is not a boundary violation.
  # `--target all` is what makes running this on Linux meaningful — without it
  # cargo resolves for the host only, and a `[target.'cfg(windows)']` dep added
  # to a pure crate would stay invisible on the very runner meant to catch it.
  #
  # `cargo tree` is run on its own line, not inside the grep pipeline. The
  # `|| true` below exists to absorb grep's exit-1-on-no-match, but attached to
  # a pipeline it absorbs a *cargo* failure just as happily — and an empty
  # `hits` then reads as "no forbidden deps". Measured: with cargo not on PATH
  # the previous one-pipeline form printed "ok" for all three pure crates and
  # exited 0, i.e. the one law the layering rests on silently verified nothing.
  if ! tree=$(cargo tree -p "$crate" --edges normal --target all --prefix none 2>&1); then
    echo "ERROR: cargo tree failed for $crate — boundary NOT verified:"
    echo "$tree" | sed 's/^/  /'
    status=1
    continue
  fi
  hits=$(printf '%s\n' "$tree" | awk '{print $1}' | sort -u | grep -E "$FORBIDDEN" || true)
  if [ -n "$hits" ]; then
    echo "BOUNDARY VIOLATION: $crate depends on:"
    echo "$hits" | sed 's/^/  - /'
    echo "  why it matters: CONCEPT §4 — the pure crates depend on seams"
    echo "  (trait Arch / MemorySource), never on a concrete OS or format."
    echo "  Trace it with: cargo tree -p $crate --edges normal --invert <crate>"
    status=1
  else
    echo "ok: $crate is free of OS/format/frontend dependencies"
  fi
done

exit $status
