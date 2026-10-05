/* A shared object holding text whose addresses and encodings are known before
 * any tool is asked: an ASCII string, a UTF-8 string in another script, and a
 * UTF-16 string. Built with: cc -shared -fPIC -O1 -o strings_planted.so strings_planted.c */
#include <uchar.h>

const char n0x_ascii[] = "n0xis-planted-ascii-7f3a";
const char n0x_utf8[] = "Привіт, n0xis";
const char16_t n0x_wide[] = u"n0xis wide ✓";
const char n0x_short[] = "abc";

const char *n0x_pick(int i) {
    return i == 0 ? n0x_ascii : i == 1 ? n0x_utf8 : i == 2 ? (const char *)n0x_wide : n0x_short;
}
