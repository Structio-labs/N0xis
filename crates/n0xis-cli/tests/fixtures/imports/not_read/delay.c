/* Planted for `imports`: a DLL importing one function from n0xnow.dll through
 * the ordinary import table and two from n0xlater.dll through the delay-load
 * table. Built by build.sh; what it imports is what the .def files state. */
__declspec(dllimport) int n0x_now(int);
__declspec(dllimport) int n0x_later_a(int);
__declspec(dllimport) int n0x_later_b(int);

/* The helper the linker's delay-load thunks call. No loader runs this image,
 * so it only has to exist; it returns what the slot holds. */
void *__delayLoadHelper2(const void *descriptor, void **slot) {
    (void)descriptor;
    return *slot;
}

__declspec(dllexport) int planted(int k) { return n0x_now(k) + n0x_later_a(k) + n0x_later_b(k); }
