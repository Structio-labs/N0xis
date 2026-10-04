// wtarget.c: the live target for oracle/windows/win_check.py.
//
// Windows has no /proc to check a live read against, so the target is its own
// oracle: it prints where its values live, and changes them only when told to
// on stdin, so every step of a check happens on cue.
//
//   x86_64-w64-mingw32-gcc -O2 -o wtarget.exe wtarget.c
//
// stdin protocol, one word per line: "hit" (hp -= 1, then print hp), "quit".
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

int hp = 1000;
volatile uint64_t marker = 0x0123456789abcdefULL;

__attribute__((noinline)) void take_damage(void) {
    hp -= 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("{\"pid\":%lu,\"hp_addr\":\"0x%llx\",\"marker_addr\":\"0x%llx\","
           "\"take_damage\":\"0x%llx\",\"hp\":%d}\n",
           (unsigned long)GetCurrentProcessId(), (unsigned long long)(uintptr_t)&hp,
           (unsigned long long)(uintptr_t)&marker,
           (unsigned long long)(uintptr_t)&take_damage, hp);
    char line[64];
    while (fgets(line, sizeof line, stdin)) {
        if (strncmp(line, "hit", 3) == 0) {
            take_damage();
            printf("{\"hp\":%d}\n", hp);
        } else if (strncmp(line, "quit", 4) == 0) {
            break;
        }
    }
    return 0;
}
