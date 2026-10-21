/* A shared object that names addresses with symbols of the types the ELF
   reader does not read as names: an STT_GNU_IFUNC function, STT_TLS
   variables (the second at a nonzero offset) and an STT_NOTYPE label. */
static int n0x_impl(void) { return 1; }
static void *n0x_resolve(void) { return (void *)n0x_impl; }
int n0x_chosen(void) __attribute__((ifunc("n0x_resolve")));
__thread int n0x_tls_a = 1;
__thread int n0x_tls_b = 2;
__asm__(".text\n.globl n0x_label\nn0x_label:\n\tret\n");
int n0x_plain(void) { return n0x_chosen() + n0x_tls_a + n0x_tls_b; }
