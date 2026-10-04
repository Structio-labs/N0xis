# hp-demo

The program and the script behind the animation at the top of the main README.

```sh
cc -O2 -g -o hp_demo hp_demo.c
N0X=/path/to/n0xis ./demo.sh     # N0X defaults to `n0x` on PATH
```

Linux, x86-64, needs `jq`. `hp_demo` keeps one value, `hp`, and loses a point
on every `SIGUSR1`, so each step of the demo happens on cue. It allows itself to
be traced, so the default Yama `ptrace_scope=1` needs no change. Every command
the script prints is the command it runs.
