/* Planted for `imports`: compiled, not linked. A relocatable object needs a
 * function and a variable it does not define (`n0x_ext_fn`, `n0x_ext_data`),
 * which a link editor resolves; it has no dynamic section. */
extern int n0x_ext_fn(int);
extern int n0x_ext_data;

int n0x_uses_both(int k) { return n0x_ext_fn(k) + n0x_ext_data; }
