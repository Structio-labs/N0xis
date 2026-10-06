# `pdbtarget` — a PE and its PDB whose contents are known in advance

`pdbtarget.c` is the source. The image and its PDB were built from it on Linux,
in a folder named `/tmp/n0xis-pdbtarget` (the PDB records that path and nothing
else of the machine), with:

    clang --target=x86_64-w64-mingw32 -O1 -g -gcodeview -gno-codeview-command-line \
      -ffile-prefix-map=$PWD=. -fdebug-compilation-dir=. -fuse-ld=lld \
      -Wl,--pdb=pdbtarget.pdb -Xlinker /pdbaltpath:pdbtarget.pdb -Xlinker /Brepro \
      -o pdbtarget.exe pdbtarget.c

What is known about it, and from where:

- From the source: the functions `record_failure`, `doubled_timeout`,
  `state_of`, `main` and the static `helper_static`, which a PDB keeps only in
  its module's stream (no public name).
- From `llvm-readobj --coff-debug-directory pdbtarget.exe`: the image's CodeView
  record, GUID `90BA008E-0CF5-2548-4C4C-44205044422E`, age 1, file name
  `pdbtarget.pdb`.
- From `llvm-pdbutil dump --summary --symbols pdbtarget.pdb`: the same GUID and
  age, and the procedures at section 1 (`.text`, RVA `0x1000`) offsets 1408,
  1424, 1440, 1488 and 1632, with code sizes 7, 10, 34, 139 and 6.
