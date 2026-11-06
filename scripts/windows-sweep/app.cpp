// Static-command input: C++ with RTTI, a virtual, known constants, known strings (ASCII, UTF-8, UTF-16).
#include <cstdio>
#include <cstdint>
extern "C" {
__attribute__((noinline)) int leaf_add(int a, int b) { return a + b * 3; }
__attribute__((noinline)) uint32_t magic_mix(uint32_t x) { return (x * 0x5bd1e995u) ^ (x >> 13); }
__attribute__((noinline)) int branchy(int x) { if (x > 10) return leaf_add(x, 1); for (int i = 0; i < x; i++) x += i; return x; }
__attribute__((noreturn)) __attribute__((noinline)) void die_now(void) { for (;;) { } }
const char planted_ascii[] = "N0XIS_STATIC_ASCII_MARKER_91";
const char planted_utf8[] = "N0XIS_ЮНІКОД_MARKER_92";
const wchar_t planted_wide[] = L"N0XIS_STATIC_WIDE_MARKER_93";
const unsigned char planted_aob[16] = {0xDE,0xC0,0xAD,0x0B,0x13,0x37,0x42,0x99,0xFE,0xED,0xFA,0xCE,0x55,0xAA,0x01,0x02};
volatile int32_t planted_i32 = 0x1CEB00DA;
volatile double planted_f64 = 1234.5678;
// a name-load next to a function pointer: the shape `bindings list` looks for
typedef int (*fn_t)(int,int);
struct binding { const char *name; fn_t fn; };
binding table_of_bindings[] = {{"get_value", leaf_add}, {"set_value", leaf_add}};
}
struct Base { virtual ~Base() {} virtual int v() { return 1; } int a = 7; };
struct Derived : Base { int v() override { return leaf_add(a, b); } int b = 9; };
__attribute__((noinline)) Base *mk() { return new Derived(); }
int main(int argc, char **argv) {
    Base *p = mk();
    printf("%s %d %u %d\n", planted_ascii, p->v(), magic_mix(argc), branchy(argc));
    printf("%s %d %f\n", planted_utf8, (int)sizeof(planted_wide), planted_f64);
    printf("%p %p %p\n", (const void*)planted_aob, (const void*)planted_wide, (void*)table_of_bindings);
    if (argc > 50) die_now();
    return (int)planted_aob[0] & 0 ;
}
