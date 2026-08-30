# Changelog

All notable changes to N0xis are recorded here. Versions follow
[Semantic Versioning](https://semver.org); dates are ISO-8601.

## [0.1.1] — 2026-08-30

Decompiler analysis-depth: three verified rungs on the path to
source-level pseudocode (see `ROADMAP.md`). Every item was confirmed on
real Win64 binaries, not just unit tests.

### Added / Improved

- **Rung 5a — branch conditions from arithmetic flags.** A `Jcc` after a
  result-keeping op (`dec ecx; jne`, `sub rax,rbx; je`, `and edx,edx; jne`)
  now reconstructs its condition instead of rendering `/*cond(jne)*/`.
  Loop latches get a visible condition again — on `CompressToolsLib.dll`,
  69 of 75 loop headers now carry a real condition (e.g.
  `while ((*(uint8_t*)(rdx.0 + rbx.3) != 0x0))`). Sound-conservative: only
  `je`/`jne` are recovered (sign/magnitude branches depend on carry/overflow
  the result alone doesn't carry and stay opaque), and 8/16-bit or memory
  destinations stay opaque.
- **Rung 4a — precise register-argument arity (Win64).** A register counts
  as a parameter only when used outside a bare pass-through call argument, so
  the lift's fixed four-register call convention no longer pegs every calling
  function at `(rcx, rdx, r8, r9)`. On `CompressToolsLib.dll` the arity-4 rate
  dropped from ~100% to a realistic 0–4 spread. A demangled C++ prototype is
  now used verbatim as the signature instead of being wrapped into a garbled
  `uint32_t <prototype>(uint64_t rcx, …)`.
- **Rung 3a — parameter typing from use.** A parameter's signature type is
  inferred from how it is used: a dereferenced pointer reads `struct_rcx_0 *rcx`
  (the C++ `this`) or `void *`; a known-Win32 argument gets its API type
  (`HANDLE`, `LPCWSTR`, …); otherwise `uint64_t`. 87 of 120 functions on
  `CompressToolsLib.dll` recover a pointer/struct parameter type.

### Notes

- Argument-arity recovery is Win64-register-specific; System V (`rdi`/`rsi`/…)
  and whole-program call-site agreement are tracked follow-ons.
- The known-API parameter-type path is unit-tested but not yet confirmed
  firing on a real target (the corpus dereferences its pointer params, so the
  struct rule wins by precedence).

## [0.1.0]

Initial v1 pipeline: static PE/ELF + live-memory analysis, optimizing SSA
decompiler with Memory-SSA (Rung 1), watchpoint→decompiled-statement
provenance, managed-runtime name recovery (IL2CPP / .NET NativeAOT / LuaJIT /
Bitsquid), and journaled patching — one `{ok,data,meta}` contract over CLI and
MCP.
