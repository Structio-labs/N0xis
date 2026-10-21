/* A shared object for a machine whose GLOB_DAT and JUMP_SLOT relocation
 * types the reader does not map (RISC-V, EM_RISCV 0xF3), built by build.sh:
 * one call to an undefined function, so the linker binds one slot to it
 * with an R_RISCV_JUMP_SLOT relocation. */
extern int n0x_ext_fn(int);
int n0x_call(int x) { return n0x_ext_fn(x) + 1; }
