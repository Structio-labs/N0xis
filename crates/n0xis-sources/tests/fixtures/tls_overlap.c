/* A shared object whose zero-filled thread-local `.tbss` shares its address
 * with the sections after it, as the linker lays it out: `.init_array` and
 * `.fini_array` (one constructor, one destructor) and `.data.rel.ro` (a table
 * of function pointers). Built with: cc -shared -fPIC -O1 -o tls_overlap.so tls_overlap.c */
__thread long n0x_tls_counter[8];

__attribute__((noinline)) void n0x_first(void) { n0x_tls_counter[0] += 1; }
__attribute__((noinline)) void n0x_second(void) { n0x_tls_counter[1] += 2; }

void (*const n0x_table[])(void) = { n0x_first, n0x_second };

__attribute__((constructor)) static void n0x_ctor(void) { n0x_tls_counter[2] = 7; }
__attribute__((destructor)) static void n0x_dtor(void) { n0x_tls_counter[3] = 0; }
