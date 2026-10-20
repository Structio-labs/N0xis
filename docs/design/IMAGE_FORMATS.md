# Design: the image-format seam

**Status: Accepted 2026-10-19 (the open decisions are decided in §7). The seam itself is not
built yet. Three parts of step 2 landed ahead of it on 2026-10-20, with the fix for 32-bit
C++ vtables: the ELF class is read, a machine this build cannot map is refused, and the
image says whether it is a program or a library; each is marked where §1 and §5 name it.**
Companion to [`CONCEPT.md`](../../CONCEPT.md) §5.1, which still describes the source seam as
it was in September (`StaticPe` only). This document is what §5.1 should become, and the
plan ROADMAP's gap-closing item 5 ("A format seam closes it the way `trait Arch` closed the
ISA one") was missing. It also supersedes ROADMAP's architectural debt "There is no format
seam", whose "nothing dispatches on file magic" no longer holds: the static image dispatches
PE and ELF by their magic (`static_image.rs:37-41`).

## 1. Why — what the current shape costs, measured

The survey of 2026-10-14 found that the knowledge of what an image *is* has leaked out of
`n0xis-sources` into every layer. Each point below carries its file:line, re-checked on
2026-10-20; a file under `crates/` is named alone where no other file there shares its name.

- **Format detection is repeated: thirteen non-test functions in nine files check a container
  signature themselves.** The static image enum (`static_image.rs:37-41`), the live Windows
  adapter twice (`live.rs:357, 397`), the unwinder three times (`unwind.rs:158, 295, 651`),
  the PE reader and its export reader three times between them (`static_pe.rs:318, 522`,
  `pe_exports.rs:52`), three passes in `n0xis-core` that look for the PE signature themselves,
  none of them for the ELF magic (`profile.rs:211`, `discover.rs:73`, `aot.rs:273-277`), and
  the WebAssembly reader (`module.rs:441`).
- **One fact, two answers.** The PE machine field is mapped in two tables that already
  disagree (`0x01c0` is `arm` in one and `unknown` in the other: `static_pe.rs:329-336`,
  `profile.rs:190-198`), and read a third time (`profile.rs:214-216`).
- **A wrong fact waiting for a reader.** *(Closed 2026-10-20: the width is `e_ident[EI_CLASS]`'s,
  and the Itanium RTTI scan and devirtualisation read it; the other passes named below still
  assume 8-byte pointers.)* The static image reports every ELF as 64-bit with
  8-byte pointers, a documented simplification (`static_image.rs:98-105, 133-139`). No answer
  is wrong because of those two fields (`is_64`, `pointer_size`) today, checked on a 32-bit ELF
  built here: the decoder is chosen from the machine field, which is right (i386), two core
  passes take the pointer size from the decoder (`typeinfer.rs:738`,
  `n0xis-core/src/switch.rs:54`), and the only readers of the fields are a PE-only RTTI scan
  (`registry.rs:314, 353, 1174`, `n0xis-cli/src/main.rs:4119`) and the fallback for a machine
  this build cannot map, whose answer is wrong whatever the bitness says (below). The first
  reader that trusts them for an ELF will be wrong. Other passes ask neither the decoder nor
  the fields and assume 8-byte pointers, among them the Itanium RTTI scan (`rtti.rs:238, 272`),
  devirtualisation (`devirt.rs:540-544`) and profile's thunk check (`profile.rs:413`); the
  RTTI scan already answers wrong on a 32-bit ELF (below).
- **Wrong answers today**, each on a file built here from known source:
  - PE machine `0x01c4` (ARMNT) is `arm` in both tables, which picks the A32 decoder
    (`arch.rs:33`), but such an image holds only Thumb-2 code: a DLL linked here
    (`clang --target=armv7-windows-msvc`, `lld-link /dll`) shows machine `0x1C4` in
    `llvm-readobj` and Thumb-2 code in `llvm-objdump`, and its first instruction is decoded as
    A32. Its export sits at an odd address, the Thumb bit set, and the PE reader returns that
    address as a function start (`static_pe.rs:305-312`); the ELF reader keys a Thumb symbol by
    its odd `st_value` the same way (`static_elf.rs:247-264`). Nothing clears bit 0.
  - A machine this build cannot map is decoded with an x86 decoder chosen by bitness
    (`arch.rs:59-69`, pinned by the test at `arch.rs:113-114`): a 32-bit RISC-V shared object
    built here is disassembled as x86, with `ok: true`. *(Closed 2026-10-20: refused without
    `--arch`, by §5 step 2's rule, on MIPS32, PowerPC32 and RISC-V 64 images built here; the
    raw machine value in an answer decoded with `--arch` is not built.)*
  - A big-endian `EM_ARM` or `EM_AARCH64` is mapped to the same name, and so the same decoder,
    as a little-endian one (`static_elf.rs:176-187`), although the comment above it says a
    big-endian machine is returned as raw hex (`static_elf.rs:169-172`). A big-endian ARMv6
    shared object linked here keeps its instruction words big-endian, and the A32 decoder reads
    every word little-endian (`arm32.rs:166`), so its code is decoded as other instructions. An
    ARMv7 one is BE-8 (code little-endian, data big-endian), and AArch64 code is little-endian
    in either byte order; both decode right.
  - The Itanium RTTI scan reads a 16-byte vtable header and 8-byte slots (`rtti.rs:238, 272`).
    A shared object built here for i686 from a two-method C++ class, with ld.lld or GNU ld,
    answers `rtti scan` with `ok: true` and no vtables, where the same source built for x86-64
    answers one: `llvm-readobj -r` puts the method slots (`R_386_32`) 8 bytes past `_ZTV1B`,
    and the scan reads the word 16 bytes past it, the first word of the class's type-info
    object, finds the value 8 there, which is not a code address, and skips the vtable.
- **Section names are policy.** `.rdata`, `.rodata`, `.data.rel.ro`, `.text` are spelled at
  more than fifteen call sites in the frontend, the CLI, the MCP server and the core (for
  example `n0xis-frontend/src/source.rs:187`, `registry.rs:313, 2120`,
  `n0xis-cli/src/main.rs:4104`, `tools.rs:984`, `profile.rs:515-517`). A format whose sections
  are called something else (`__TEXT,__cstring`) is invisible to them.
- **`.pdata` is parsed in four places**, `.eh_frame` in two (`static_pe.rs:522`,
  `discover.rs:68`, `eh.rs:402`, `unwind.rs:295`; `eh.rs:293`, `unwind.rs:485`).
- **`n0xis-core` walks PE headers itself** (profile, discovery, the NativeAOT reader:
  `profile.rs:203`, `discover.rs:68`, `aot.rs:271`), although CONCEPT §3 rule 2 puts everything
  format-specific behind an adapter. The walks read through `MemorySource` at a module base, so
  they also run on live modules (`aot.rs:311`), and what replaces them must read an image as it
  is mapped (§2).
- **Facts no reader exposes at all:** the entry point (nothing reads `e_entry` or
  `AddressOfEntryPoint`), the ISA revision (ARMv6 vs ARMv7 — nobody tells the A32 decoder,
  which is built for every revision, `arm32.rs:109-129`, so in ARMv6 code it accepts encodings
  ARMv6 does not have: `movw` and `ubfx`, which llvm-mc 23.1.1 rejects for `armv6` as ARMv6T2
  encodings, and the A32 `sdiv` of the optional divide extension, which llvm-mc rejects for
  `armv7a` too; the revision therefore has to tell ARMv6 from ARMv6T2 as well as from ARMv7),
  and imports grouped by the library that provides them (the only import query answers one
  slot at a time, `n0xis-sources/src/lib.rs:340-343`).
- **Runtime metadata is welded to a format variant:** Itanium RTTI is reached only through
  the ELF variant (`registry.rs:317, 422, 1163`, `n0xis-cli/src/main.rs:4097`), keyed on `_ZTV`
  (`rtti.rs:259`; a Mach-O spells it `__ZTV`).

Adding a third format to this shape means a third arm in every one of those places. That is
the trap the project's own rule names: when a class of defect has bitten, rebuild the seam
instead of extending past it.

## 2. What the seam must answer

One trait every format reader implements, with **no default methods** (a defaulted method
on a wrapper here once silently did nothing). Each answer is a typed fact with its origin;
"not read" and "none" are different values.

| Question | Type (sketch) | Notes |
|---|---|---|
| What machine is this? | `Machine { isa, revision, bits, endian }` or `Unrecognized { raw }` | One table maps it to the set of decoders the image can hold (§7.2), the pointer size, which never chooses a decoder, and the default ABI. Revision is how ARMv6, ARMv6T2 and ARMv7 differ. |
| Is it a program or a library? | `Linkage::{Executable, SharedLibrary}` | What the header says: ELF `ET_EXEC`, or an `ET_DYN` with `DF_1_PIE` or with a `PT_INTERP` and no `DT_SONAME`, is a program, and every other `ET_DYN` a library; a PE is a library by `IMAGE_FILE_DLL`. A library's classes may be derived from in the program that loads it, which the image cannot see, so devirtualisation takes no declared class there (built 2026-10-20 on today's readers, `n0xis_sources::Linkage`). |
| How is it loaded? | `segments()` | The loader's view; reads go through these. |
| What are its parts? | `sections()` with a typed `Role` | `Code`, `CString`, `ReadOnlyData`, `Data`, `ZeroFill`, `Unwind(kind)`, `Stubs`, `ImportPointers`, `Other`. Passes ask for a role, never a name. |
| What does it name? | `symbols()` | Raw name, kind, `Extent::{Stated(n), Unknown}`, origin, Thumb bit. |
| What does it need? | `imports()` | Libraries in load order; each reference with `LibraryRef::{Binds(i), Named(i), SelfImage, MainExecutable, Flat, Weak, Unattributed { why }}` and `Reach::{Stub(va), Slot(va), Index(n)}`; the whole answer is `Read(..)` or `NotRead { why }`. `Binds` is a library the format binds the import to (a PE import descriptor, a Mach-O two-level ordinal); `Named` is one only named for it (an ELF version requirement: ELF binding is flat). `Index` reaches a WebAssembly import by its function index, since it has no stub or slot address ([`WASM.md`](WASM.md) §5, decision 1). |
| What does it offer? | `exports()` | |
| Where does code start? | `declared_starts()` | Each start with why: entry point, export, function-starts table, symbol, unwind entry; optional extent. |
| What does memory hold at load? | `loaded_bytes()` | The loader's view before binding (§7.3): rebases and relative relocations applied, binds left unbound; what a slot is bound to comes from `binding_at`. |
| What was wrong with it? | `findings()` | `Truncated`, `Contradiction`, `Unsupported`, `Encrypted`. |

Opening is one function per format, `open(bytes, &OpenOptions) -> Opened`, where
`Opened` is `Thin(image)` or `NeedsSlice(slices)` for universal files, so choosing a slice
is a typed step with the choices listed, not a guess. `OpenOptions` carries the slice for
universal files and the base, machine and memory map for raw firmware, which declares
nothing it was not given.

**Detection is one registry** of `(sniff, open)` pairs, WebAssembly's among them
([`WASM.md`](WASM.md) stage 2). The static path, the live adapters and the unwinder all use
it; the copies §1 lists go. Eight of them read an image only as it is mapped, at a module
base, not as a file (the live Windows adapter, the unwinder and the core's walks), and the
export reader reads it both ways (a header read at a module base, `profile.rs:274`, and the
file's bytes, `static_pe.rs:471`), so the registry needs an opener over the mapped layout as
well as over file bytes, or those copies cannot go. The live Linux adapter is a second ELF
reader, re-reading each module's file (`live_linux.rs:285-345`), and goes the same way.

**One adapter, not one per format.** A single `ImageSource` implements today's
`MemorySource`, `SymbolProvider` and `ModuleProvider` from those facts, so symbol lookup,
import slots, symbol sizes and thunk targets are computed once. The current static enum
collapses into it.

## 3. Runtime metadata is its own unit

RTTI (two ABIs), Objective-C, Go's function table, the IL2CPP and NativeAOT readers and PDB
are not parts of a format reader. Each becomes a metadata unit:

```
trait MetadataReader {
    fn name(&self) -> &'static str;
    fn applies(&self, image: &dyn Image) -> Applicability;   // with why, if not
    fn read(&self, image: &dyn Image) -> MetadataFacts;       // names, starts, classes, types
}
```

A unit sees only the `Image` answers — roles, symbols, "what is bound at this slot" — so the
same Objective-C reader works on any image that has the sections, and the same Itanium RTTI
reader works on ELF and Mach-O. Units register through the existing capability registry,
like any plugin (CONCEPT §4, the `n0xis-frontend` row): no privileged core.

## 4. The hostile-input contract

Every reader and every metadata unit meets the same contract, checked mechanically:

1. **Total.** No input ends a command without its JSON. The boundary catches panics and
   reports them as an internal error, which tests count as a failure.
2. **No allocation sized by a count the file states.** Counts are bounded by the bytes that
   could hold them. A lint forbids `with_capacity`, `resize` and `vec![_; n]` in reader
   modules, except at sites named in an exemption list with the reason each is bounded, the
   way `every_command_has_one_implementation.rs:24-52` names its exceptions. The correct code
   that steps 3 and 5 move unchanged has fifteen such sites outside its tests, each with its
   reason: the length of a list or slice already parsed or read (`static_elf.rs:208`,
   `static_pe.rs:170`, `pe_exports.rs:167`, `aot.rs:378, 680`, `script_json.rs:113`,
   `n0xis-il2cpp/src/lib.rs:226`), a count checked against the bytes first (`aot.rs:226` after
   `aot.rs:204-210`, `aot.rs:463` after `aot.rs:456`, `metadata.rs:192` after
   `metadata.rs:152`), a constant cap (`aot.rs:358, 861, 875`) or a constant table's length
   (`metadata.rs:145`), or a 16-bit count (`aot.rs:291`). The `.pdata` code that step 4 merges
   into one parser has three more: `eh.rs:475` and `eh.rs:549`, each a count capped by a
   constant and checked against the bytes first (`eh.rs:466-473`, `:539-547`), and
   `unwind.rs:322`, a capacity of `ex_size / 12` entries taken once the `ex_size` bytes the
   exception directory states have been read (`unwind.rs:321`). That read is bounded only by
   the reader behind it: a `MemorySource` clamps it to what is mapped before allocating
   (`static_pe.rs:445`, `live.rs:525`), while the Windows debug adapter's own reader allocates
   the stated size first (`debug.rs:414`).
3. **Bounded loops.** Every walk is bounded by bytes or a budget; graphs (export tries,
   fixup chains) keep a visited set.
4. **The loader's structures win** over what a file claims elsewhere (segments over
   sections), and a disagreement is a finding, not a silent pick.
5. **Every reader ships with its oracle:** a fixture built here from known source (or planted
   by a committed generator where no toolchain here can build one), the independent tool's
   output recorded beside it with a test that re-records it when the tool is present, and at
   least 2 000 corrupted copies per fixture, each of which must read as an answer, with or
   without findings, or as an error, never a panic or a single allocation larger than a
   constant the reader states times the input's length (the WebAssembly reader states
   `2 * size_of::<Located>()` bytes per input byte,
   `n0xis-wasm/tests/mutated.rs:15-20, 290, 319`).

## 5. Migration — no behaviour change until a step says so

1. **Pin today.** List the tests that already pin each fact, add a temporary comparison of
   old and new facts on every committed fixture and on a sweep of the system's own images.
   That comparison only proves "unchanged" (rung 5), which is all this step claims.
2. **One `Machine` table.** This step changes answers on purpose: a 32-bit ELF reports 4-byte
   pointers (a column the decoder choice never reads: an x32 ELF built here is `ELF32` with
   x86-64 code), and the passes that assume 8-byte pointers (§1) read that column instead; the
   PE `0x01c0` disagreement is settled; the machine answers §1 lists as wrong are corrected;
   and so is the Thumb bit: bit 0 of an ARM ELF function symbol's value or of an ARMNT PE
   export's address is cleared from the start it gives and kept as the Thumb indication of
   §2's `symbols()`. The ARMNT machine answer and the Thumb bit are the machine and symbol
   parts of [`ISA_AND_LIFT.md`](ISA_AND_LIFT.md) §8, decision 4, and the rest of that
   decision's mode at an address is built in this step too, starting with its first
   sub-decision, where the mode enters the ISA seam (a mode parameter on `Arch::decode`, which
   changes the public trait, or a per-source map of modes with two `Arch` objects): the mode
   per address range, and data inside code, from ELF mapping symbols; the direct call edge as
   a source of the mode; and a mode of their own for PLT stubs and linker thunks. Every change
   of answers this document makes, and each that work makes, goes on this step's list, with
   the measurement beside it, and the developer reviews the list at this step; a change that
   needs something a later step builds lands with that step, or, when that step must not
   change an answer, as a step of its own right after it (§7). Each change is listed and
   checked against the format's own specification before it lands.
3. **PE and ELF behind `Image`**, as thin wrappers over the current parsing; the static
   enum becomes `ImageSource`. Right after it comes a step of its own on step 2's list: the
   read view's announced change of answers (§7.3).
4. **Roles replace section names** at every call site; one `.pdata` parser, one
   `.eh_frame` parser; the core stops walking headers.
5. **Metadata units:** RTTI, IL2CPP, NativeAOT and PDB move out of the format paths.
6. **Mach-O** lands as the third `Image`: thin and universal files; bind opcodes, chained
   fixups and the classic symbol and indirect-symbol tables (images from before the dynamic
   loader's info commands); Objective-C as a metadata unit. A Mach-O reader drafted earlier is
   held outside the repository. It is not in this shape (it adds a third variant to today's
   static enum, commands named after the format, and Mach-O names to a list of section
   names), so it moves behind the seam rather than being merged as it is.
7. **Raw firmware** as the fourth.

Each step is its own commit series with the gate green; steps 1, 3 and 4 must not change a
single answer, and the comparison from step 1 is what shows it, re-recorded after each
earlier step that changes answers on purpose (step 2, and the step right after step 3).
WebAssembly modules ([`WASM.md`](WASM.md) stage 2) are an `Image` on the same registry and
can follow step 3.

## 6. Done when

- Format detection exists once: no code but the registry's entries checks a container
  signature, whether to choose a format or to re-walk a header, and a test fails if a second
  copy appears (the `one_fact_one_place` pattern).
- No call site outside `n0xis-sources` names a section or reads a header field.
- A 32-bit ELF, a PE, a thin and a universal Mach-O built here from known source each answer
  every question in §2, and every answer agrees with an independent reader (`llvm-readobj`,
  `llvm-objdump`, `llvm-nm`).
- An image with no dynamic-loader info (imports only in the classic tables) lists its
  imports grouped by library, checked on a planted fixture whose answer is known before the
  question is asked.

## 7. Decisions

Decided 2026-10-19. The measurements below were re-taken on 2026-10-20 on objects and images
built here from known source (clang, LLD and the LLVM tools 23.1.1; gcc 16.2.1 with GNU ld
2.47; for the i686 and x86-64 Windows DLLs, the mingw-w64 cross gcc 16.2.0 with GNU ld
2.47.20260726).

1. **Symbol names: each symbol carries its raw spelling and a typed decoration, stated by
   whatever produced it; one function gives the source-level name from the two**, so the
   pipeline sees one spelling on every format and no lookup site strips anything. The
   decoration is a type, for example `Decoration::{None, LeadingUnderscore, Stdcall(n),
   Fastcall(n), Vectorcall(n), ElfVersion { version, default }}`, carried on `Symbol` in
   `n0xis-contracts` with a schema version bump, so that every producer has to state it: the
   image readers, those that build symbols outside them (`pdb_syms.rs:59`,
   `annotation_syms.rs:143`, `live_linux.rs:324`, the signature matcher and the importer of
   managed metadata), and the snapshot, which reads `Symbol` back from a captured file
   (`snapshot.rs:45-46, 65-69`, `n0xis-frontend/src/source.rs:302-304`). A snapshot captured
   before the bump states no decoration: it is read with a decoration that says so, never with
   `None`, which would claim a spelling no producer stated, and its names are served as
   captured, as they are today. This refines §2's `symbols()`. Three further parts:
   - **Mach-O first:** a C name's leading `_` is the decoration `LeadingUnderscore`, exactly
     one removed when there is one; a name without it (`start`, an Objective-C method, an
     assembler label) has no C spelling and is served as written. This is the only part that
     changes no answer the tool gives today.
   - **Undecorating i386 COFF and PDB names, and stripping the ELF version suffix, are
     separate announced changes of answers** on step 2's list, not part of the seam. An export
     keeps its export name (`name@8`) as its identity, since that is what a loader resolves,
     and a version suffix is never removed where two definitions would then share one name.
   - **Calibrated on spelling:** a Mach-O built here that calls `abort`, `_exit` and
     `__stack_chk_fail` must end the block at all three, and an ELF built here that defines a
     returning `_abort` must not. Whether the tables cover a Mach-O platform's C library is a
     separate question, measured against that SDK's own headers when one is available here,
     and recorded as not measured until then.

   *Why.* (a) The tables are keyed by C names (`noreturn.rs:28-112`, matched exactly, ignoring
   ASCII case, at `noreturn.rs:133-135`), and the spelling differs by format: on C files built
   here, `llvm-nm` shows `_abort`, `__exit`, `_strlen` and `___stack_chk_fail` for Mach-O
   (x86-64 and arm64), the same prefix for i686 COFF, and `abort`, `_exit`, `strlen`,
   `__stack_chk_fail` for ELF and x86-64 COFF. Served raw, a Mach-O's calls to `abort`,
   `_exit` and `__stack_chk_fail` would not end their blocks, the soundness defect
   `noreturn.rs:4-9` exists to prevent. Stripping at each lookup instead either ignores the
   format (an ELF's own returning `_abort` would become no-return) or needs the format at each
   site that derives a bare name (twelve `rsplit('!')` in `n0xis-core`). (b) Decoration is not
   one rule, and removing it is not always right: a shared object built here with GNU ld
   defines both `foo@V1` and `foo@@V2`, literally so in `.strtab`, and stripping the suffix
   serves both as `foo` and loses which is the default; a mingw i386 DLL linked here exports
   `sc@8`, the name a loader looks up; and `__vectorcall` decorates on x86-64 too (`vc@@16`
   from clang for x86-64 COFF and for Mach-O). (c) A field on `Symbol` makes every producer
   state its spelling, which a rule inside one reader cannot: the PDB keeps the decorated
   public name (`n0xis-pdb/src/lib.rs:115-116`) and reaches the tables through `pdb_syms.rs`,
   not through an image reader.

   *What would change it.* A Mach-O built here whose prefixed name has a C spelling other than
   "one `_` removed". The `$`-suffixed variants (`_fopen$UNIX2003`-style) are not checked,
   because no such SDK is installed here; one would add a decoration, not a rule at a lookup
   site.

   *Built.* The decoration and its schema version in step 6, with the Mach-O rule. The i386
   and PDB undecoration and the ELF version suffix are on step 2's list; each reads the
   decoration, so it lands with step 6, by §5 step 2's rule for a change that needs a later
   step.

2. **An explicit `--arch` chooses among what the image can hold; it never overrides what the
   image declares.** §2's one `Machine` table maps each declaration to the set of decoders the
   image can contain, and pointer width is a separate column that never chooses a decoder:
   ELF `EM_ARM` gives {A32, T32}; PE `0x01c4` gives {T32}; Mach-O armv6 and armv7 give
   {A32, T32}; `EM_X86_64` gives {x86-64} whatever the ELF class; arm64_32 gives {A64};
   `EM_386` and PE `0x014c` give {x86-32}. Three further parts:
   - **Outside the set is refused, inside it is a choice.** The refusal names what the header
     declares and the set. A thin image is a set of one slice and a universal file a set of
     several, so a missing slice and a mismatched `--arch` are the same typed refusal.
   - **Where nothing is declared** (`--bytes`, a live process, a snapshot, raw firmware), the
     flag is the declaration, as today. A declared machine this build cannot map is refused
     without `--arch`; with it, the flag is the declaration and the raw machine value is shown
     in the answer.
   - **A separately named override** that decodes against the header waits for a measured
     need.

   *Why.* (a) An explicit request the tool cannot honour is refused, not replaced: answering a
   different question is "the worst of the three options"
   (`n0xis-frontend/src/source.rs:343-351`), and decoding one instruction set as another is
   the confident wrong answer CONCEPT §5.2 records. Today an explicit `--arch` always wins
   (`arch.rs:56-58`), so once the same flag also picks a universal file's slice, a script that
   passes it routinely would decode a thin image of another architecture without a word.
   (b) Width cannot define a disagreement: an x32 ELF built here
   (`clang -target x86_64-linux-gnux32`) is `ELF32` with `EM_X86_64` and x86-64 code, and an
   arm64_32 Mach-O object built here has the 32-bit magic `0xFEEDFACE` and an A64 CPU type, so
   a width rule would refuse a correct `--arch x64` and choose x86-32. (c) A family is not
   enough either: a PE `0x01c4` image holds only Thumb-2 code (§1), so accepting `arm32` there
   as a choice inside the family would accept a decode known to be wrong.

   *What would change it.* A measured need to decode against the header (code the header does
   not describe, or a header known to lie) that `--bytes` over an extracted window cannot
   serve. Then the separately named override is added, and `--arch` itself is never loosened.

   *Built.* Step 2, with the `Machine` table. The refusal of a machine this build cannot map
   landed ahead of it (2026-10-20), and the bitness-fallback test (`arch.rs:113-114`) changed
   with it. The tests that pin the rest of today's behaviour (an explicit
   `--arch` over the header, `arch.rs:110` and `n0xis-frontend/src/source.rs:686`) change, and are on step 2's list with the measurement beside
   each; the help texts change with them: `ARCH_HELP` (`n0xis-cli/src/main.rs:745-746`), and
   `ARCH_HELP_NO_HEADER` (`n0xis-cli/src/main.rs:750-751`) where `diff` uses it
   (`n0xis-cli/src/main.rs:1155`), since `diff.functions` then reads the header. The pickers
   that ignore the header where the target can be a file (`registry.rs:983, 2360`,
   `il2cpp_caps.rs:618, 685`) go through the one picker in the same step, or the rule does not
   hold everywhere; on the live-only paths that call `resolve_arch`, the flag stays the
   declaration.

3. **The read view is the loader's view before binding, and what a slot is bound to is one
   required query.** On a static image, `MemorySource::read` serves the image as the loader
   leaves it before binding, at its preferred base: rebases and relative relocations applied,
   every bind left unbound (zero for a chained bind; whatever the file holds for a PE import
   slot, an ELF GOT or PLT slot, or a lazy pointer). It is stored as the file plus a sparse
   overlay of the words the loader writes with a value the file does not already hold, so the
   file's own bytes stay available without a second copy; the raw view becomes an explicitly
   named accessor, added with its first consumer. §2's `loaded_bytes()` is this view. Three
   further parts:
   - **What a slot is bound to is one required query, a method of the `Image` trait (§2) with
     no default**, for example `binding_at(va) -> {Rebased(target), SelfDefinition { target,
     interposable }, Import(ImportRef), Unbound { why }}`. It answers every pointer-sized slot
     a relocation or bind names; against a symbol the image defines, that is each ELF
     machine's absolute pointer relocation (`R_X86_64_64`, `R_AARCH64_ABS64`, `R_386_32`,
     `R_ARM_ABS32`), `GLOB_DAT` and `JUMP_SLOT`, and Mach-O's binds to the image itself. It
     replaces today's `JUMP_SLOT`-only path (`static_elf.rs:320-322`). It is what §3's "what
     is bound at this slot" means.
   - **Devirtualisation, RTTI base walking and profile's thunk check consult it** whenever
     they follow a pointer, instead of reading the bytes and treating zero as unknown
     (`devirt.rs:540-547`, `rtti.rs:264-277`).
   - **Calibrated on a default-visibility C++ vtable built with both linkers:**
     devirtualisation must resolve both slots, to the targets `llvm-readobj -r` names. A check
     that compares two tables of zeros is not a calibration.

   *Why.* (a) The consumers were written for the loader's view: a zero slot is
   "relocation-supplied, unresolved", and an address is followed when it is there
   (`rtti.rs:264-277`, `devirt.rs:540-547`). In a chained-fixup image the file view gives them
   an encoding, which is neither a value nor an error: an arm64 Mach-O library linked here
   holds `0x0010000000000330` where the pointer is `0x330`. (b) The question is already open on
   ELF, and today's answer depends on the linker: the same C pointer table built here for
   x86-64 reads as zeros from an ld.lld shared object, and as addresses from lld with packed
   relative relocations and from GNU ld, which writes each value into its slot as well as into
   its `R_X86_64_RELATIVE` entry (`llvm-objdump -s`, with `llvm-readobj -r` naming the
   entries); built for i686, whose `REL` entries keep the value in the slot, it reads as
   addresses from both linkers. No other ELF machine was measured for this. A mingw-w64 x86-64
   DLL linked here already holds, at its preferred base, the addresses its base relocations
   would write. So the overlay, which holds only words that differ from the file, is empty for
   PE, for x86-64 ELF linked by GNU ld or with packed relocations, for i686 ELF, and for Mach-O
   fixed up by opcodes; chained fixups and the `RELA` relative entries ld.lld leaves as zero
   fill it. (c) A bind is not written into the bytes, because the bytes cannot say "imported
   from X". But a C++ vtable in a default-visibility shared object built here for x86-64, with
   either linker, is filled by `R_X86_64_64` relocations against the image's own method
   definitions and reads as zeros (built for i686 with either linker, and for ARMv7 and
   AArch64 with ld.lld, its slots carry `R_386_32`, `R_ARM_ABS32` and `R_AARCH64_ABS64` and
   read as zeros too), so without an answer for a self-bound slot devirtualisation and RTTI
   gain nothing in the common C++ case; `thunk_to` is the PLT-stub query
   (`n0xis-sources/src/lib.rs:345-362`) and does not cover it.

   *What would change it.* A consumer that needs the file's own encoded words (a static file
   patcher, a byte-signature generator over data, a comparison with `llvm-objdump -s`): it gets
   the named raw accessor over the same overlay, which is still not the default. Ruling
   relocation processing out of scope for ELF would leave "one view" different per format,
   the shape this seam exists to remove.

   *Built.* `binding_at` is a required method of the `Image` trait from step 3, where the read
   view stays as it is today and the query answers only today's facts (an import slot's
   symbol, `static_pe.rs:411`, `static_elf.rs:540`, and a `JUMP_SLOT` bound to a function the
   image defines, `static_elf.rs:320-322`), so step 3 changes no answer; no `SymbolProvider`
   method is added for it before then. Applying ELF relative relocations, answering every
   self-bound slot and moving devirtualisation, RTTI and profile onto the query are one
   announced change of answers on step 2's list, landing as a step of its own immediately
   after step 3, never inside steps 1, 3 or 4. Mach-O's chained fixups fill the overlay in
   step 6. The on-disk caches are keyed by the analyzer's build
   (`n0xis-pipeline/src/lib.rs:95-117`), so a changed view is never served from an old cache.

4. **Commands: one format-neutral command per question; metadata commands are named by their
   unit.** `imports` becomes a capability in the registry, so the CLI, the MCP server and
   `serve` reach it alike: libraries in load order, each reference with its attribution and
   how it is reached, or `NotRead { why }`, with format-specific detail in typed fields inside
   it. A degraded PE parse answers `NotRead`, and an ELF says that its binding is flat.
   Metadata commands are named by the unit, as `rtti scan`, `aot symbols` and `symbols add`
   already are, and each refuses with its `Applicability` reason when its unit does not apply;
   which units apply, and why the others do not, is reported by `profile`, which moves into
   the registry. No command is named after a container format: the held reader's
   `macho.imports` becomes `imports`, and its `macho.objc` becomes the Objective-C unit's
   command.

   *Why.* (a) The surface already chose this axis: no registered capability is named after a
   container format (none is `pe.*`, `elf.*` or `macho.*`; grep `Capability::new(` in
   `n0xis-frontend`), and `rtti.scan` answers two ABIs in one shape by checking the image
   (`registry.rs:1159-1165`). (b) "Imports grouped by library" is asked of every format
   planned: §6 here, the recompiler's input ([`RECOMPILER.md`](RECOMPILER.md) §2) and a
   WebAssembly module's imports ([`WASM.md`](WASM.md) stage 2). One command per question keeps
   one entry per question in each guard (`docs_match_binary.rs`, `no_silent_empty_answer.rs`,
   `front_doors_agree.rs`), where commands per format would add a schema per format to every
   one of them. (c) Neither "not parsed" nor "named but not bound" may read as a plain list: a
   PE whose import table did not parse must not report an empty one
   (`static_pe.rs:58-61, 124-131`), and an ELF's provider comes only from a version
   requirement, "informative, not authoritative" (`static_elf.rs:287-290`).

   *What would change it.* A format turning out to have a whole surface with no counterpart in
   other formats that users need as commands (a full load-command or data-directory dump);
   even then a per-format block in `profile` comes first, unless that surface grows questions
   of its own. Or the registry adopting a different naming rule for the whole surface.

   *Built.* `imports` in step 3, for PE and ELF; a new command changes no existing answer.
   Mach-O fills it in step 6 and WebAssembly in its stage 2. The unit report in `profile`, and
   `profile` in the registry (`every_command_has_one_implementation.rs:38` lists it as not
   there yet), come with the metadata units in step 5. The MCP `module_list` description,
   which promises "a static PE's imports/module table" and returns only the image
   (`tools.rs:695-704`, `static_pe.rs:239-244`), is corrected when `imports` lands.
