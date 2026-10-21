/* Planted for a slot two relocations bind: built by build.sh, then patched by
 * plant.py so that the JUMP_SLOT relocation against the undefined
 * n0x_ext_fn names the same slot as the one against the defined
 * n0x_local_fn. No linker emits that; a file can say it. */
int n0x_local_fn(void) { return 1; }
extern int n0x_ext_fn(void);
int n0x_call_local(void) { return n0x_local_fn() + 2; }
int n0x_call_ext(void) { return n0x_ext_fn() + 3; }
