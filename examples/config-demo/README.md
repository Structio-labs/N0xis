# config-demo

The program and the script behind the animation at the top of the main README.

```sh
cc -O2 -g -o config_demo config_demo.c
N0X=/path/to/n0xis ./demo.sh     # N0X defaults to `n0x` on PATH
```

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
  key as `key + (key * 2) * 4 + 7`, which is the source's `key * 13 + 7`.
- The answer gives addresses, not the names `config` and `decrypt_config`: names
  from the binary's symbols are not carried into it yet.
