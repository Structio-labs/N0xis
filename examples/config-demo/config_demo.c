// config_demo.c: a tiny target for the N0xis live-loop demo.
//
// It keeps its settings encrypted and decrypts them into a buffer at start and
// again whenever it receives SIGUSR1 (`kill -USR1 <pid>`), so a demo can make
// the write happen on cue. The plaintext exists only in memory.
//
//   cc -O2 -g -o config_demo config_demo.c
//   ./config_demo &
#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

// "server=updates.example.net;interval=300;retry=5", XOR-ed with a key that
// changes after every byte (key = key * 13 + 7, starting at 0x5a).
static const unsigned char sealed[] = {
    0x29, 0xfc, 0xbe, 0x15, 0x6b, 0xcf, 0x9d, 0x52, 0x72, 0x45, 0xd5, 0x5f,
    0x53, 0xb6, 0x26, 0x0a, 0xd2, 0xc8, 0xf1, 0x83, 0x32, 0xa8, 0x5e, 0xd9,
    0x37, 0x45, 0xbf, 0xd2, 0xe8, 0xa1, 0xbd, 0x8d, 0x8c, 0xd8, 0x00, 0xbe,
    0x9d, 0xed, 0x70, 0x7c, 0xd0, 0x24, 0x20, 0x39, 0xaf, 0xd8, 0x9d
};

char config[64];

static volatile sig_atomic_t reload_pending = 0;

static void on_reload(int sig) {
    (void)sig;
    reload_pending = 1;
}

__attribute__((noinline)) void decrypt_config(void) {
    unsigned char key = 0x5a;
    for (size_t i = 0; i < sizeof sealed; i++) {
        config[i] = (char)(sealed[i] ^ key);
        key = (unsigned char)(key * 13 + 7);
    }
}

int main(void) {
#ifdef __linux__
    // With Yama ptrace_scope=1 (the default on many distributions) a process
    // may only read the memory of its own descendants. Let any process of the
    // same user attach, so n0xis can read and watch this one.
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
    signal(SIGUSR1, on_reload);
    decrypt_config();
    printf("config-demo: pid %d, settings loaded (send SIGUSR1 to reload them)\n", (int)getpid());
    fflush(stdout);
    for (;;) {
        pause();
        if (reload_pending) {
            reload_pending = 0;
            decrypt_config();
        }
    }
}
