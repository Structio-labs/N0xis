/* The live target. It plants known values, prints where they are, and prints every 100 ms what those bytes hold:
   "did the write land" is answered by this process, not by the tool. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NOI __attribute__((noinline))
volatile int32_t  p_i32  = 0x1CEB00DA;
volatile int16_t  p_i16  = 0x7A5B;
volatile int64_t  p_i64  = 0x0DEADBEEFCAFEF00DLL;
volatile float    p_f32  = 32125.625f;
volatile double   p_f64  = 1234.56789125;
char              p_str[] = "N0XIS_LIVE_ASCII_MARKER_77";
char              p_utf8[] = "N0XIS_ЖИВИЙ_MARKER_78";
wchar_t           p_wide[] = L"N0XIS_LIVE_WIDE_MARKER_79";
unsigned char     p_aob[16] = {0xB1,0x6B,0x00,0xB5,0xAC,0xDC,0x77,0x31,0x9E,0x3F,0xC4,0x10,0xE7,0x55,0x2A,0x8D};
volatile uint64_t writeme = 0x1111111111111111ULL;
volatile uint32_t pinme   = 0x22222222;
volatile uint8_t  patchme[8] = {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7};
volatile int32_t  counter = 0;
volatile int32_t  toggled = 500;              /* flips at each 40th tick: for by-transition */
struct grp { int32_t a; float b; double c; int32_t d; } p_grp = { 0x51525354, 6.5f, 77.125, 0x61626364 };
struct leaf { char pad[0x20]; int32_t value; };
struct mid  { char pad[0x10]; struct leaf *next; };
struct mid *volatile root_ptr;
volatile uint32_t lcg_seed = 987654321;       /* the combo printed below is generated from it */
volatile float aabb[8];

NOI int hooked(int delta) {                   /* called from the tick loop every 100 ms */
    int r = counter;
    r = r + delta;
    counter = r;
    if (r % 40 == 0) toggled = toggled + 1;
    return r * 2;
}
NOI int ret_const(void) { return 0x11223344; }
NOI uint32_t magic_mix(uint32_t x) { return (x * 0x5bd1e995u) ^ (x >> 13); }
NOI int tick_loop_step(int d) { return hooked(d) + (int)magic_mix(d); }

static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l) { return DefWindowProcW(h, m, w, l); }
static volatile HWND g_hwnd;
static DWORD WINAPI window_thread(void *arg) {
    WNDCLASSW wc = {0}; wc.lpfnWndProc = wndproc; wc.hInstance = GetModuleHandleW(0); wc.lpszClassName = L"N0xSweepTarget";
    wc.hbrBackground = CreateSolidBrush(RGB(12, 200, 34));
    RegisterClassW(&wc);
    HWND h = CreateWindowExW(0, wc.lpszClassName, L"N0XIS TARGET \x0416\x0418\x0412\x0418\x0419", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 40, 320, 240, 0, 0, wc.hInstance, 0);
    g_hwnd = h;
    MSG m; while (GetMessageW(&m, 0, 0, 0) > 0) { TranslateMessage(&m); DispatchMessageW(&m); }
    return 0;
}
static DWORD WINAPI idle_thread(void *arg) { for (;;) Sleep(1000); return 0; }

/* A LuaJIT-shaped heap, GC64 header: `len` at +0x14, text at +0x18; tagged TValues refer to the bases. */
#define STRING_TAG (0x1FFFBULL << 47)
static void plant_str(unsigned char *base, const char *s) {
    *(uint32_t *)(base + 0x14) = (uint32_t)strlen(s);
    for (size_t i = 0; s[i]; i++) ((volatile unsigned char *)base)[0x18 + i] = s[i];
}
static const char *lua_tokens[] = {"up", "down", "left", "right", "zzsweepmarker"};

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct mid *m = (struct mid *)calloc(1, sizeof *m);
    struct leaf *lf = (struct leaf *)calloc(1, sizeof *lf);
    lf->value = 0x7C0FFEE7; m->next = lf; root_ptr = m;

    unsigned char *page = (unsigned char *)VirtualAlloc(0, 0x8000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    for (int i = 0; i < 5; i++) plant_str(page + 0x100 + 0x100 * i, lua_tokens[i]);
    uint64_t *arr = (uint64_t *)(page + 0x1000);
    int seq[] = {0, 1, 1, 2, 3, 0, 2};
    for (int i = 0; i < 7; i++) arr[i] = STRING_TAG | (uint64_t)(page + 0x100 + 0x100 * seq[i]);
    /* a GCtab whose array part is 1-based: slot 0 unused, 1..4 are the strings; a one-node hash part, empty */
    unsigned char *tab = page + 0x2000;
    uint64_t *tabarr = (uint64_t *)(page + 0x3000);
    for (int i = 0; i < 4; i++) tabarr[i + 1] = STRING_TAG | (uint64_t)(page + 0x100 + 0x100 * i);
    *(uint64_t *)(tab + 0x10) = (uint64_t)tabarr;
    *(uint64_t *)(tab + 0x28) = (uint64_t)(page + 0x4000);
    *(uint32_t *)(tab + 0x30) = 5;
    *(uint32_t *)(tab + 0x34) = 0;

    /* a UI element: min.x at base + 0xa4, seven contiguous floats */
    unsigned char *ui = page + 0x5000;
    float af[7] = {100, 100, 0, 200, 200, 0, 50};
    memcpy(ui + 0xa4, af, sizeof af);

    /* the first direction sequence from the LCG, as `lua seedscan` models it */
    char combo[128] = "";
    { uint32_t s = lcg_seed; static const char *dirs[] = {"left", "up", "right", "down"};
      for (int i = 0; i < 12; i++) { s = s * 1664525u + 1013904223u; if (i) strcat(combo, ","); strcat(combo, dirs[s >> 30]); } }

    HANDLE ht = CreateThread(0, 0, idle_thread, 0, 0, 0);
    HANDLE hw = CreateThread(0, 0, window_thread, 0, 0, 0);
    (void)ht; (void)hw;
    while (!g_hwnd) Sleep(10);

    unsigned char *rc_imm = 0;
    for (unsigned char *q = (unsigned char *)ret_const; q < (unsigned char *)ret_const + 32; q++)
        if (*(uint32_t *)q == 0x11223344) { rc_imm = q; break; }

    printf("PID %lu\n", GetCurrentProcessId());
    printf("TID %lu\n", GetCurrentThreadId());
    printf("BASE 0x%llx\n", (unsigned long long)GetModuleHandleW(0));
#define A(n, p) printf("ADDR " n " 0x%llx\n", (unsigned long long)(p))
    A("p_i32", &p_i32); A("p_i16", &p_i16); A("p_i64", &p_i64); A("p_f32", &p_f32); A("p_f64", &p_f64); A("p_str", p_str); A("p_utf8", p_utf8); A("p_wide", p_wide); A("p_aob", p_aob);
    A("writeme", &writeme); A("pinme", &pinme); A("patchme", patchme); A("counter", &counter); A("toggled", &toggled); A("p_grp", &p_grp);
    A("root_ptr", &root_ptr); A("mid", m); A("leaf", lf); A("leaf_value", &lf->value); A("lcg_seed", &lcg_seed);
    A("hooked", hooked); A("ret_const", ret_const); A("rc_imm", rc_imm); A("magic_mix", magic_mix); A("step", tick_loop_step); A("main", main);
    A("toolhelp", GetProcAddress(GetModuleHandleW(L"kernel32"), "CreateToolhelp32Snapshot")); A("page", page); A("tab", tab); A("ui", ui); A("ui_minx", ui + 0xa4); A("hwnd", g_hwnd);
    for (int i = 0; i < 5; i++) printf("LUA %s 0x%llx\n", lua_tokens[i], (unsigned long long)(page + 0x100 + 0x100 * i));
    printf("COMBO %s\n", combo);
    printf("READY\n");

    uint64_t n = 0;
    for (;;) {
        int v = tick_loop_step(1);
        unsigned char *hb = (unsigned char *)hooked;
        printf("T n=%llu i32=%08x write=%016llx pin=%08x patch=%02x%02x%02x%02x rc=%08x hb=%02x%02x%02x%02x%02x%02x cnt=%d tog=%d fg=%d v=%d\n",
               (unsigned long long)++n, (unsigned)p_i32, (unsigned long long)writeme, (unsigned)pinme,
               patchme[0], patchme[1], patchme[2], patchme[3], (unsigned)ret_const(),
               hb[0], hb[1], hb[2], hb[3], hb[4], hb[5], counter, toggled, GetForegroundWindow() == g_hwnd, v);
        Sleep(100);
    }
    return 0;
}
