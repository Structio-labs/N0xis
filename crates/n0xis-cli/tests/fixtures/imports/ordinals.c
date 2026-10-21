/* A PE32 that imports one function by name and one by ordinal only from a
   library it names, and one from kernel32.dll: the import table's two shapes
   of entry, at the PE32 slot width. */
__declspec(dllimport) int by_name(void);
__declspec(dllimport) int by_ordinal(void);
__declspec(dllimport) void __stdcall ExitProcess(unsigned code);

void start(void) { ExitProcess((unsigned)(by_name() + by_ordinal())); }
