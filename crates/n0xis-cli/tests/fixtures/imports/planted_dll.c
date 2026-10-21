/* The library ordinals-i686.exe imports from, with an export of each shape a
   PE export table holds: a named function, a function by ordinal only, a
   named variable, and a forwarder to another library (planted_dll.def). */
int a_value = 41;
int by_name(void) { return 1; }
int by_ordinal(void) { return a_value + 1; }
int _DllMainCRTStartup(void *h, unsigned reason, void *r) { (void)h; (void)reason; (void)r; return 1; }
