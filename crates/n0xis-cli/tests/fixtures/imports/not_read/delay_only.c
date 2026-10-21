/* Planted for `imports`: a DLL whose only import is delay-loaded, one
 * function from n0xlater.dll. Built by build.sh. */
__declspec(dllimport) int n0x_later_a(int);

void *__delayLoadHelper2(const void *descriptor, void **slot) {
    (void)descriptor;
    return *slot;
}

__declspec(dllexport) int planted(int k) { return n0x_later_a(k); }
