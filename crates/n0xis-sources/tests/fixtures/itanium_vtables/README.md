# `itanium_vtables` — C++ vtables whose places are known in advance

`vtables.cpp` is the source: seven polymorphic classes, single and multiple
inheritance and a pure virtual method, and two virtual calls of `Base::g`
(`Base::h`, through `this`; `fresh`, through an object whose vtable it stored).
`build.sh` builds it with clang and ld.lld 23.1.1 for `i686-linux-gnu`,
`armv7-linux-gnueabihf` (A32, `-marm`), `armv7-thumb-linux-gnueabihf` (the same
target with `-mthumb`: every method is a Thumb function, and a slot holds its
address with bit 0 set), `x86_64-linux-gnu` and `aarch64-linux-gnu`, each as:

- `vt-<target>.so` — a shared object, linked as the 32-bit defect was measured
  (`-O1 -fPIC -shared -nostdlib -fuse-ld=lld`). Its method slots are symbolic
  relocations and read as zero in the file.
- `vt-<target>` — a static non-PIE executable. Its slots and `type_info`
  pointers hold their addresses in the file, and a vtable address is an
  immediate in the code.
- `stripped/vt-<target>` — that executable after `llvm-objcopy --strip-all
  --keep-symbol='_ZT*' --wildcard`: only the vtable and `type_info` symbols are
  left, so nothing but the slots says which method is where. `--strip-all`
  removes non-allocated sections only, so every byte the loader maps is the
  unstripped file's and that file's recordings hold for it; the tests check
  both facts.

and `vt-aarch64_be-linux-gnu.so`, a big-endian (`EI_DATA` = 2) shared object of
the same source, which the RTTI paths refuse.

`vbases.cpp` holds classes with virtual bases (`Mid : virtual VBase`, `Leaf :
Mid`), built as `vb-i686-linux-gnu.so` and `vb-x86_64-linux-gnu.so`: their
vtables begin with virtual-base offsets, so `_ZTV` + two pointers is their
`type_info` slot, which `llvm-readobj -r` shows.

`vbinline.cpp` holds classes with virtual bases and no key function (`M :
virtual A, virtual B`; `N : virtual P`, where `P` has no data and shares
`N`'s vptr) and two without (`Plain`, `Tail`), built with clang `-O2` as
`vbi-<target>.so` and `vbi-<target>` for i686 and x86-64. clang emits no VTT
for any of them, so only their tables say that `_ZTV` + two pointers is not
their vptr: the word that names their own `_ZTI` is further in.

`outside.cpp` has `Sub : Base` with `Sub::f` in an executable section of its
own (`hot_code`), built as `vo-x86_64-linux-gnu`: the word where Sub's first
method is holds an address outside `.text` and inside the code. `Base::h` on a
`Sub` runs `Sub::g` on the processor: with
`int main() { Sub s; s.v = 0; const Base &b = s; printf("%d\n", b.h()); }`
appended, `clang++ -O1` built, run on this machine's x86-64 processor, printed
123 (`Sub::g`'s 41 * 3; `Base::g` gives 6), and `main` calls `_ZNK4Base1hEv`.
`notcode.cpp` is the same classes with `Sub::f` written in assembly into a
writable `.data` that is not executable, built as `vd-x86_64-linux-gnu`: the
word where Sub's first method is holds an address outside every executable
section (`llvm-nm` gives `Sub::f` kind `D`).

`flow.cpp` builds objects with placement new on different paths, built as
`vf-x86_64-linux-gnu`: `g` builds a `B` only on the branch that returns and
calls `f` on the other, `built` builds a `D` and calls `f`, `rebuilt` builds a
`D` and, on one path, a `B` over it before the call. `flow_run.cpp` is the
processor's answer (each call prints f + 1; `D::f` 43, `B::f` 7): `g(&d, 0)`
is 43, `built` 43, `rebuilt` 43 or 7 by its argument. `processor_run.sh`
builds and runs it with the other run and records it in `processor_run.txt`.

`vbnortti.cpp` holds classes with a virtual base, compiled with `-fno-rtti`
(`HM : virtual P`, `HL : HM`, `P` without data, so it shares their vptr; `Q`
without one), built with clang `-O2` as `vn-<target>.so` and `vn-<target>` for
i686 and x86-64 and as `vn-armv7-linux-gnueabihf` (A32): no `type_info`, no
VTT, and every word before their first method zero. `vbnortti_run.cpp` is the
processor's answer to where their vptr points: `_ZTV` + 20 on i686 and + 40 on
x86-64 for `HM` and `HL`, + 8 and + 16 for `Q` (`processor_run.txt`).

`vbindirect.cpp` holds classes whose virtual base is indirect and shares their
vptr (`Leaf : Mid : virtual P`, `P` without data; `Leaf2 : Mid2 : virtual E`,
`E` empty), with `Plain` as the control, built with clang `-O1` as the shared
objects `vy-<target>.so` for i686 and x86-64: their `type_info` pointers are
symbolic relocations, and `llvm-readobj -r` names the word that holds each
class's own `_ZTI` and the method after it.

`vr-<target>.so` is `vtables.cpp` built as the shared objects are, with
`-Wl,-Bsymbolic -Wl,-z,pack-relative-relocs`, for i686 and x86-64: their method
slots are relative relocations packed into a `RELR` table, which `llvm-readobj
-r` prints one word per line.

`plugin.cpp` has `Plugin`, which nothing in it derives from, and
`Plugin::drive`, which calls `run` through `this`, and `Codec` after it, so
that `Plugin`'s table is not the last, built for x86-64 as
`vp-x86_64-linux-gnu.so`, `vp-x86_64-linux-gnu` (a static executable) and
`vp-pie-x86_64-linux-gnu` (a position-independent executable: `ET_DYN`, with
`PT_INTERP` and `DF_1_PIE`). The two `ET_DYN`s are linked `-Bsymbolic
--apply-dynamic-relocs`: their slots are relative relocations whose values
are in the file as well, as GNU ld writes them. Their recordings also hold the program headers
and the dynamic table, which say which `ET_DYN` is a program. `plugin_run.cpp`
is the processor's answer for the library: linked against the committed
`vp-x86_64-linux-gnu.so` itself, a `My : Plugin` the program defines makes
`drive` return 1007, where `Plugin::run` gives 1001 (`processor_run.txt`).

`external.cpp` has `Local : Ext`, where `Ext` is defined in no image here, and
`Alone`, built as `vx-<target>` for i686 and x86-64: `_ZTI5Local` is the
one-base layout and its base pointer links to 0.

What is known about them, and from where:

- From the source: the classes, their bases, the method each table holds
  first, and which calls go through which slot.
- From `llvm-nm` (`*.nm.txt`): where every `_ZTV…` and `_ZTI…` object is.
- From `llvm-readobj` (`*.readobj.txt`): the ELF class (`Class: 32-bit (0x1)`
  or `64-bit (0x2)`); for a shared object, the relocation that fills each slot,
  which names the method there, and each `type_info`'s base pointer, which
  names the base's `_ZTI`; for an executable, the bytes of `.rodata`, where its
  vtables are.

`processor_run.cpp` is the processor's answer to which method `Base::h`'s
virtual call runs on a `Derived`: `Derived::g` (it prints 42; `Base::g` would
give 6). `processor_run.sh` builds and runs it for x86-64 and i686, then
`flow_run.cpp` for x86-64, `vbnortti_run.cpp` for both and `plugin_run.cpp`
against `vp-x86_64-linux-gnu.so`, and writes `processor_run.txt`. They are the
evidence for refusing a dispatch through a parameter's declared type when the
class has a subclass, and through a construction that does not dominate the
call, for refusing the `vn-*` classes with a virtual base where the scan
reads their first method, and for taking a library's classes as derived from
in the program that loads it; no test reads them.

`record.sh` writes the recordings. `cargo test -p n0xis-sources --features
oracle --test itanium_vtable_recordings_match_the_tools` fails if one no longer
says what the tool prints, or if `llvm-objcopy` no longer makes a stripped
fixture from its executable byte for byte.
