# config-demo

The program and the script behind the animation at the top of the main README.

```sh
cc -O2 -g -o config_demo config_demo.c
N0X=/path/to/n0xis ./demo.sh     # N0X defaults to `n0x` on PATH
```

The binary is built and released as `n0xis`; set `N0X`, or `ln -s n0xis n0x` somewhere on `PATH`.

Linux, x86-64, needs `jq`. `config_demo` keeps its settings encrypted and
decrypts them into a buffer at start and on every `SIGUSR1`, so the write the
demo watches for happens on cue. It allows itself to be traced, so the default
Yama `ptrace_scope=1` needs no change. Every command the script prints is the
command it runs.

What the run shows, and how it was checked (2026-10-05, Linux, gcc `-O2 -g`):

- `scan aob` finds the plaintext once, at the address `nm` gives `config`.
- `provenance trace` reports the write at `decrypt_config+0x36`, the byte store
  `mov %cl,(%rdi,%rdx,1)` in `objdump`, inside the function `nm` names
  `decrypt_config`.
- The decompiled loop computes `sealed[i] ^ key` into the buffer and updates the
  key in two statements, `rcx.4 = v1 + v1 * 2` and `v1 = v1 + rcx.4 * 4 + 7`,
  which together are the source's `key * 13 + 7`.
- The answer gives addresses, not the names `config` and `decrypt_config`: names
  from the binary's symbols are not carried into it yet.

Re-checked 2026-10-20 with the same source built three ways, against `llvm-nm`
and `objdump`. The store (`instruction_va`) was right on all three. The
containing function (`function_va`) was right only on gcc `-O2`: on clang `-O2`
and on gcc `-O1` it is the loop head inside `decrypt_config` (the target of the
loop's backward jump), answered `ok:true` with no note, and on clang `-O2` the
decompiled context holds only the loop's first block, without the key update.
`cc` is clang on some systems, so build with gcc to see the run above.
