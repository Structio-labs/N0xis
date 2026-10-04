// hp_demo.c: a tiny target for the N0xis live-loop demo.
//
// It holds one value, `hp`, and loses one point every time it receives
// SIGUSR1 (`kill -USR1 <pid>`), so a demo can trigger the write on cue
// instead of waiting for a timer.
//
//   cc -O2 -g -o hp_demo hp_demo.c
//   ./hp_demo &
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

int hp = 100;

static volatile sig_atomic_t hit_pending = 0;

static void on_hit(int sig) {
    (void)sig;
    hit_pending = 1;
}

__attribute__((noinline)) void take_damage(void) {
    hp -= 1;
}

int main(void) {
#ifdef __linux__
    // With Yama ptrace_scope=1 (the default on many distributions) a process
    // may only read the memory of its own descendants. Let any process of the
    // same user attach, so n0xis can read and watch this one.
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
    signal(SIGUSR1, on_hit);
    printf("hp-demo: pid %d, hp = %d (send SIGUSR1 to take a hit)\n", (int)getpid(), hp);
    fflush(stdout);
    for (;;) {
        pause();
        if (hit_pending) {
            hit_pending = 0;
            take_damage();
            printf("hit! hp = %d\n", hp);
            fflush(stdout);
        }
    }
}
