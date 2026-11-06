// One body against the original on generated inputs. Linked with one body TU that defines bh_call and the BH_* facts.
// Prints one JSON line: inputs, same_full, same_low, differ, crash, plus the first difference.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <link.h>

uint64_t G_BASE, G_RDI, G_RSI, G_RDX, G_RCX, G_R8, G_R9;
uint8_t bh_fs[4096];
__attribute__((visibility("default"))) uint64_t emu_ext_const(void) { return 0x00c0ffee0badf00dull; }

// Facts about this body, from the generated TU.
extern uint64_t bh_call(uint64_t *a);
extern const char *BH_NAME, *BH_KINDS;  // source's argument kinds: v value, n small, b buffer, s string
extern int BH_RET_BITS, BH_RET_SIGNED, BH_VOID;  // the body's declared return
extern int BH_RET_STR, BH_FP;
extern int BH_SRC_BITS;                          // the source's return width; 0 = void

static int isnan_any(uint64_t x) {
    // As a double, or either 32-bit half as a float.
    uint32_t lo = (uint32_t)x, hi = (uint32_t)(x >> 32);
    return ((x >> 52) & 0x7ff) == 0x7ff && (x << 12) || ((lo >> 23) & 0xff) == 0xff && (lo << 9) || ((hi >> 23) & 0xff) == 0xff && (hi << 9);
}
static sigjmp_buf jb;
static volatile int inside;
static void on_sig(int s) { if (inside) { inside = 0; siglongjmp(jb, s); } _exit(70 + s); }

static const uint64_t VAL[] = {0, 1, 2, 3, 7, 8, 0x2a, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000, 0xdeadbeefcafe1234, 0xffffffffffffffff, 0x8000000000000000, 0x7fffffffffffffff, 0x0123456789abcdef, 0x3ff8000000000000, 0xc004000000000000, 0x3fc00000, 0xc0400000};
#define NVAL (sizeof VAL / sizeof VAL[0])
static uint64_t st = 0x4E30B0D1E5;
static uint64_t rnd(void) { st ^= st << 13; st ^= st >> 7; st ^= st << 17; return st; }

#define BUFN 6
#define BUFSZ 256
static uint8_t proto[BUFN][BUFSZ], ba[BUFN][BUFSZ], bb[BUFN][BUFSZ];

static void gen_args(int idx, const char *k, uint64_t *v, int *bufslot) {
    // deterministic per input
    for (int i = 0; i < 6; i++) {
        bufslot[i] = -1;
        char c = k[i] ? k[i] : 'v';
        if (c == 'v') {
            int m = idx < (int)(NVAL * 3) ? 0 : 1;
            v[i] = m == 0 ? VAL[(idx * (i + 1) + i * 3) % NVAL] : (rnd() >> (rnd() % 64));
        } else if (c == 'n') {
            v[i] = rnd() % 33;
        } else if (c == 'c') {
            v[i] = rnd() % 256;
        } else if (c == 'm') {
            v[i] = rnd() % 8;
        } else {
            bufslot[i] = i;
            for (int j = 0; j < BUFSZ; j++) proto[i][j] = (uint8_t)rnd();
            if (c == 's') {
                int len = rnd() % 40;
                // Lower-case text, digits and a few signs: strings a string function sees, common prefixes among the buffers.
                for (int j = 0; j < len; j++) proto[i][j] = (j < 3 && (idx & 1)) ? "abc"[j] : "abcdefgh 0123-xyz"[rnd() % 17];
                proto[i][len] = 0;
            } else if (c == 'S') {
                // ascending int32 array, what a search expects
                int32_t *a = (int32_t *)proto[i];
                int32_t x = -50;
                for (int j = 0; j < 60; j++) { x += rnd() % 7; a[j] = x; }
            } else if (c == 'B') {
                for (int j = 0; j < BUFSZ; j++) proto[i][j] = (uint8_t)(rnd() % 5);
            }
        }
    }
}

int main(int argc, char **argv) {
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (!h) { printf("{\"harness_error\":\"open %s\"}\n", dlerror()); return 2; }
    void *f = dlsym(h, BH_NAME);
    if (!f) { printf("{\"harness_error\":\"no symbol\"}\n"); return 2; }
    Dl_info di;
    dladdr(f, &di);
    G_BASE = (uint64_t)di.dli_fbase - 0x40000000ull;  /* the library is linked at this base; a body's literal addresses hold only if it loaded there */
    if (G_BASE) { printf("{\"harness_error\":\"loaded at %p\"}\n", di.dli_fbase); return 2; }
    typedef uint64_t (*F)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    F orig = (F)f;
    { static const int sigs[] = {SIGSEGV, SIGFPE, SIGILL, SIGBUS, SIGABRT, SIGALRM, SIGTRAP}; for (unsigned q = 0; q < 7; q++) { struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = on_sig; sa.sa_flags = SA_NODEFER; sigaction(sigs[q], &sa, 0); } }
    // canary in the fake TLS block
    memset(bh_fs, 0x5a, sizeof bh_fs);
    int inputs = atoi(argv[2]);
    int same_full = 0, same_low = 0, differ = 0, crash = 0, orig_crash = 0, zext_ok = 1, sext_ok = 1, buf_diff = 0;
    char first[256] = "", first_nan[256] = "";
    int differ_nan = 0;
    int src = BH_SRC_BITS, w = BH_VOID ? 0 : BH_RET_BITS;
    uint64_t smask = src >= 64 ? ~0ull : (1ull << src) - 1;
    int lowbits = w < src ? w : src;
    uint64_t lmask = lowbits >= 64 ? ~0ull : lowbits == 0 ? 0 : (1ull << lowbits) - 1;
    for (int i = 0; i < inputs; i++) {
        uint64_t a[6], ca[6], cb[6];
        int slot[6];
        gen_args(i, BH_KINDS, a, slot);
        memcpy(ba, proto, sizeof ba);
        memcpy(bb, proto, sizeof bb);
        for (int j = 0; j < 6; j++) { ca[j] = slot[j] >= 0 ? (uint64_t)ba[j] : a[j]; cb[j] = slot[j] >= 0 ? (uint64_t)bb[j] : a[j]; }
        struct itimerval t = {{0, 0}, {0, 100000}}, z = {{0, 0}, {0, 0}};
        uint64_t so = 0, ro = 0;
        int sig;
        if ((sig = sigsetjmp(jb, 1))) { orig_crash++; continue; }
        inside = 1; setitimer(ITIMER_REAL, &t, 0);
        so = orig(ca[0], ca[1], ca[2], ca[3], ca[4], ca[5]);
        setitimer(ITIMER_REAL, &z, 0); inside = 0;
        // A pointer the original returned into its own buffer is compared as an offset into that buffer: same meaning in the copy.
        int ptr_ret = 0;
        for (int j = 0; j < 6; j++) if (slot[j] >= 0 && so >= (uint64_t)ba[j] && so <= (uint64_t)ba[j] + BUFSZ) { so = so - (uint64_t)ba[j] + (uint64_t)bb[j]; ptr_ret = 1; }
        if ((sig = sigsetjmp(jb, 1))) { crash++; if (crash >= 6) break; if (!first[0]) snprintf(first, sizeof first, "signal %d on input %d args %llx %llx %llx %llx", sig, i, (unsigned long long)a[0], (unsigned long long)a[1], (unsigned long long)a[2], (unsigned long long)a[3]); continue; }
        G_RDI = cb[0]; G_RSI = cb[1]; G_RDX = cb[2]; G_RCX = cb[3]; G_R8 = cb[4]; G_R9 = cb[5];
        inside = 1; setitimer(ITIMER_REAL, &t, 0);
        ro = bh_call(cb);
        setitimer(ITIMER_REAL, &z, 0); inside = 0;
        uint64_t sv = so & smask;
        uint64_t full = ro;
        if (w && w < 64) { full = ro & ((1ull << w) - 1); if (BH_RET_SIGNED && (full >> (w - 1))) full |= ~0ull << w; }
        int nan_in = 0;
        if (BH_FP) for (int j = 0; j < 4; j++) nan_in |= isnan_any(a[j]);
        if (BH_RET_STR) {
            // Same text = same answer: a literal lives at another address in the copy.
            int eq = 0;
            if ((sig = sigsetjmp(jb, 1))) { crash++; continue; }
            inside = 1;
            eq = strcmp((const char *)so, (const char *)ro) == 0;
            inside = 0;
            if (eq) { same_full++; } else { differ++; if (!first[0]) snprintf(first, sizeof first, "input %d: different text", i); }
            continue;
        }
        int bd = memcmp(ba, bb, sizeof ba) != 0;
        if (bd) buf_diff++;
        int f_eq = (src == 0 || (w && (full & smask) == sv)) && !bd;
        int l_eq = (src == 0 || (w && (ro & lmask) == (sv & lmask))) && !bd;
        if (lowbits && lowbits < src) {
            uint64_t lo = sv & lmask;
            uint64_t se = (lo >> (lowbits - 1)) ? (lo | (~0ull << lowbits)) & smask : lo;
            if (sv != lo) zext_ok = 0;
            if (sv != se) sext_ok = 0;
        }
        if (f_eq) same_full++;
        else if (l_eq) same_low++;
        else if (nan_in) { differ_nan++; if (!first_nan[0]) snprintf(first_nan, sizeof first_nan, "NaN input %d args %llx %llx: source %llx body %llx", i, (unsigned long long)a[0], (unsigned long long)a[1], (unsigned long long)sv, (unsigned long long)ro); }
        else { differ++; if (!first[0]) snprintf(first, sizeof first, "input %d args %llx %llx %llx %llx: source %llx body %llx%s", i, (unsigned long long)a[0], (unsigned long long)a[1], (unsigned long long)a[2], (unsigned long long)a[3], (unsigned long long)sv, (unsigned long long)ro, bd ? " (buffers differ)" : ""); }
    }
    printf("{\"inputs\":%d,\"same_full\":%d,\"same_low\":%d,\"differ\":%d,\"crash\":%d,\"orig_crash\":%d,\"buf_diff\":%d,\"ext_only\":%d,\"src_bits\":%d,\"body_bits\":%d,\"differ_nan\":%d,\"first\":\"%s\"}\n", inputs, same_full, same_low, differ, crash, orig_crash, buf_diff, zext_ok || sext_ok, src, w, differ_nan, first[0] ? first : first_nan);
    return 0;
}
