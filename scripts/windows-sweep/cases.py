"""What the static part asks, of every input and of the stateful commands. Addresses come from nm, objdump and wasm-objdump."""

ASCII = "N0XIS_STATIC_ASCII_MARKER_91"
AOB = "DE C0 AD 0B 13 37 42 99"

# Real programs, as a path under --images. `heavy` runs the per-function commands too; `truth` is where the scorer reads DWARF
# from. A program with neither is compared with its twin and no more.
IMAGES = [
    dict(tag="just", file="just/release/just", heavy=True),
    dict(tag="ripgrep-nog", file="ripgrep/release-nog/rg"),
    dict(tag="fd-pe", file="fd/release-pe/fd.exe", heavy=True, truth="fd/release-pe/fd.exe"),
    dict(tag="fd-a64", file="fd/release-a64/fd", truth="fd/release-a64/fd"),
    dict(tag="fd-dev-pe", file="fd/dev-pe/fd.exe", truth="fd/dev-pe/fd.exe"),
    dict(tag="ripgrep-pe", file="ripgrep/release-pe/rg.exe", heavy=True, truth="ripgrep/release-pe/rg.exe"),
]
HEAVY = {"function.noreturn", "function.summary", "function.typeflow", "function.layout"}


def case(id, *args, stdin=None, refuses=None, must=None, bound=60, ignore=(), kind_only=False):
    """`ignore`: keys that are the length of a stored path. `kind_only`: both refuse, and the words are what the OS does with such a path."""
    return dict(id=id, args=list(args), stdin=stdin, refuses=refuses, must=must, bound=bound, ignore=ignore, kind_only=kind_only)


def per_input(T):
    out = []
    for t, d in T.items():
        F = "{IN}" + d["f"]
        code = hex(d["code"])
        data = hex(d["data"] or d["code"])
        start, size = hex(d["data"] & ~0xfff) if d["data"] else hex(d["code"]), "0x300"
        def c(leaf, *a, tag="", must=None):
            id = f"{leaf.replace(' ', '.')}{'+' + tag if tag else ''}__{t}"
            out.append(case(id, *leaf.split(), *a, refuses=refused(id, t), must=must))
        c("profile", "--file", F)
        c("imports", "--file", F)
        c("why", "--addr", code, "--file", F)
        c("contradictions", "--file", F, "--limit", "40")
        c("module list", "--file", F)
        c("disasm", "--addr", code, "--count", "8", "--file", F)
        for leaf in ("ir build", "ir explain", "ir dot", "ir value-set", "ir deobfuscate"):
            c(leaf, "--addr", code, "--file", F)
        c("ir slice", "--addr", code, "--reg", d["reg"], "--file", F)
        c("ir manifest", "--file", F, "--limit", "20")
        c("function discover", "--file", F, "--limit", "60")
        c("function discover", "--file", F, "--pdata", "--limit", "60", tag="pdata")
        c("function trace", "--addr", code, "--file", F, "--depth", "2")
        c("function noreturn", "--file", F, "--limit", "20")
        c("function summary", "--file", F, "--limit", "10")
        c("function typeflow", "--file", F, "--limit", "10")
        c("function layout", "--file", F, "--limit", "10")
        c("function eh", "--file", F, "--addr", code)
        c("decomp pseudo", "--addr", code, "--file", F)
        c("decomp pseudo", "--addr", code, "--file", F, "--style", "goto", tag="goto")
        c("decomp pseudo", "--addr", code, "--file", F, "--explain", tag="explain")
        c("xref to", "--addr", data, "--file", F)
        c("xref from", "--addr", code, "--file", F)
        c("xref string", "--query", "MARKER", "--file", F, "--limit", "20")
        c("rtti scan", "--file", F)
        c("analyze", "--file", F, "--limit", "10")
        c("find", "--string", ASCII, "--file", F, "--limit", "10", must=[hex(d["data"])] if d["data"] else None)
        c("find", "--bytes", AOB, "--file", F, "--limit", "10", tag="bytes", must=[hex(d["aob"])] if d["aob"] else None)
        c("find", "--string", "N0XIS_STATIC_WIDE", "--utf16", "--file", F, "--limit", "10", tag="utf16", must=[hex(d["wide"])] if d["wide"] and d["f"].endswith((".exe", ".dll")) else None)
        c("strings", "--file", F, "--limit", "200")
        c("strings", "--file", F, "--contains", "MARKER", "--limit", "20", tag="contains", must=[ASCII] if d["data"] else None)
        c("strings", "--file", F, "--encoding", "utf16le", "--limit", "20", tag="utf16")
        c("mem read", "--addr", data, "--size", "32", "--file", F, must=["4e 30 58 49 53"] if d["data"] else None)
        c("mem span", "--addr", data, "--size", "32", "--file", F)
        c("scan value", "--type", "u8", "--value", "0x4e", "--file", F, "--start", start, "--size", size, "--save-as", "sv_" + t, "--force")
        c("scan filter", "--from", "sv_" + t, "--criterion", "exact", "--value", "0x4e", "--file", F, "--save-as", "sf_" + t, "--force")
        c("scan aob", "--pattern", "4E 30 ?? 49", "--file", F, "--start", start, "--size", size)
        c("scan dissect", "--start", start, "--size", "64", "--file", F)
        c("scan group", "--field", "u8=78", "--field", "u8=48", "--file", F, "--start", start, "--size", size, "--limit", "10")
        c("bindings list", "--file", F, "--limit", "20")
        c("const identify", "--addr", hex(d["magic"] or d["code"]), "--file", F, must=["5bd1e995"] if d["magic"] and t not in ("wasm", "arm64") else None)
        c("sig gen", "--file", F)
        c("sig validate", "--at", code, "--len", "8", "--file", F)
        c("aot symbols", "--file", F, "--limit", "10")
        c("il2cpp symbols", "--file", F, "--limit", "10")
        c("il2cpp icalls", "--file", F, "--limit", "10")
        c("il2cpp obj", "--addr", data, "--file", F)
        c("il2cpp metadata", "--file", F, "--limit", "10")
        c("annotate name", "--addr", code, "--value", "нове_ім'я", "--file", F)
        c("annotate type", "--addr", code, "--value", "int (*)(int)", "--file", F)
        c("annotate comment", "--addr", code, "--value", "коментар with \"quote\" and \\ slash", "--file", F)
        c("annotate var", "--addr", code, "--var", "a1", "--value", "змінна", "--file", F)
        c("annotate vartype", "--addr", code, "--var", "a1", "--value", "uint32_t", "--file", F)
        c("annotate bookmark", "--addr", code, "--file", F)
        c("annotate show", "--addr", code, "--file", F)
        c("decomp pseudo", "--addr", code, "--file", F, tag="after-annotate")
        c("annotate list", "--file", F)
        c("annotate rm", "--addr", code, "--file", F)
        c("snapshot dump", "--name", "snap_" + t, "--file", F, "--start", start, "--size", "0x200", "--force")
        c("snapshot info", "snap_" + t)
        c("mem read", "--addr", start, "--size", "16", "--snapshot", "snap_" + t, tag="snapshot")
        c("strings", "--snapshot", "snap_" + t, "--limit", "20", tag="snapshot")
        c("find", "--string", "N0XIS", "--snapshot", "snap_" + t, "--limit", "5", tag="snapshot")
        c("function discover", "--snapshot", "snap_" + t, "--limit", "20", tag="snapshot")
    return out


def stateful(T):
    B = "48 89 c8 48 83 c0 01 c3"
    I = "{IN}"
    A = I + "app.exe"
    app = T["app"]
    code, data = hex(app["code"]), hex(app["data"])
    c = case
    return [
        c("init", "init", "--dir", "{W}initdir", "--name", "sweep"),
        c("project.info", "project", "info"),
        c("project.cache", "project", "cache"),
        c("project.cache+clear", "project", "cache", "--clear"),
        c("doctor", "doctor"),
        c("guide", "guide"), c("guide+topic", "guide", "scan"), c("guide+brief", "guide", "--brief"),
        c("global+pretty", "--pretty", "project", "info"), c("global+json", "--json", "project", "info"), c("global+quiet", "--quiet", "profile", "--file", A),
        c("global+version", "--version"), c("global+help", "--help"), c("help+decomp", "decomp", "pseudo", "--help"),
        c("config.set", "config", "set", "update.check", "false"),
        c("config.get", "config", "get", "update.check"),
        c("capability.list", "capability", "list"),
        c("capability.run", "capability", "run", "decode", "--args", '{"bytes":"48 89 c8 c3","addr":"0x1000"}', must=["mov"]),
        c("capability.run+bad", "capability", "run", "no.such.thing", "--args", "{}", refuses="unknown-capability"),
        c("symbols.add", "symbols", "add", "--file", I + "pdbtarget.exe", "--pdb", I + "pdbtarget.pdb"),
        c("symbols.add+wrongpdb", "symbols", "add", "--file", A, "--pdb", I + "pdbtarget.pdb", refuses="no-codeview"),
        c("function.discover+pdb", "function", "discover", "--file", I + "pdbtarget.exe", "--limit", "60", must=["record_failure"]),
        c("type.struct", "type", "struct", "--name", "Conn", "--field", "0x0:retries:int", "--field", "0x4:timeout:float", "--size", "16"),
        c("type.struct+bad-field", "type", "struct", "--name", "Bad", "--field", "retries:int", refuses="bad-field"),
        c("scan.group+hex-field", "scan", "group", "--field", "u8=0x4e", "--file", A, "--start", data, "--size", "0x40"),
        c("annotate.var+real", "annotate", "var", "--addr", code, "--var", "v1", "--value", "змінна", "--file", A),
        c("annotate.vartype+real", "annotate", "vartype", "--addr", code, "--var", "rcx", "--value", "uint32_t", "--file", A),
        c("decomp+renamed-variable", "decomp", "pseudo", "--addr", code, "--file", A, must=["змінна"]),
        c("annotate.rm+real", "annotate", "rm", "--addr", code, "--file", A),
        c("type.enum", "type", "enum", "--name", "St", "--member", "OPEN=1", "--member", "CLOSED=2"),
        c("type.list", "type", "list"), c("type.rm", "type", "rm", "--name", "St"),
        c("selection.save", "selection", "save", "--name", "s1", "--start", "0x1000", "--end", "0x1010", "--label", "мітка"),
        c("selection.list", "selection", "list"), c("selection.show", "selection", "show", "--name", "s1"), c("selection.clear", "selection", "clear", "--name", "s1"),
        c("dump.save+content", "dump", "save", "--name", "d1", "--kind", "pseudo", "--content", "вміст дампа"),
        c("dump.save+file", "dump", "save", "--name", "d2", "--kind", "ir", "--file", I + "payload.txt"),
        c("dump.save+stdin", "dump", "save", "--name", "d3", "--kind", "ir", stdin="from stdin ю\n"),
        c("dump.list", "dump", "list", ignore=("size",)), c("dump.show", "dump", "show", "--name", "d1", "--kind", "pseudo", must=["вміст дампа"]), c("dump.show+file", "dump", "show", "--name", "d2", "--kind", "ir"), c("dump.rm", "dump", "rm", "--name", "d1", "--kind", "pseudo"),
        c("name.colon", "dump", "save", "--name", "a:b", "--kind", "ir", "--content", "x", refuses="dump-save-failed"),
        c("name.traversal", "dump", "save", "--name", "..\\escape", "--kind", "ir", "--content", "x", refuses="dump-save-failed"),
        c("name.NUL", "dump", "save", "--name", "NUL", "--kind", "ir", "--content", "x"),
        c("name.CON", "dump", "save", "--name", "CON", "--kind", "ir", "--content", "x"),
        c("name.trailing-dot", "dump", "save", "--name", "tail.", "--kind", "ir", "--content", "x"),
        c("table.add", "table", "add", "--table", "t1", "--name", "hp", "--addr", "0x1000", "--type", "i32", "--description", "опис"),
        c("table.list", "table", "list"), c("table.show", "table", "show", "--table", "t1"), c("table.rm", "table", "rm", "--table", "t1", "--name", "hp"),
        c("snapshot.list", "snapshot", "list", ignore=("size",)),
        c("patch.list", "patch", "list"), c("patch.show+absent", "patch", "show", "--id", "nope", refuses="patch-show-failed"), c("patch.undo+nothing", "patch", "undo", "--pid", "999999", refuses="no-patches"),
        c("disasm+bytes", "disasm", "--addr", "0x1000", "--bytes", B, "--count", "4"),
        c("disasm+bytes32", "disasm", "--addr", "0x1000", "--bytes", "55 89 e5 5d c3", "--arch", "x86", "--count", "4"),
        c("ir.build+bytes", "ir", "build", "--addr", "0x1000", "--bytes", B),
        c("decomp+bytes", "decomp", "pseudo", "--addr", "0x1000", "--bytes", B),
        c("why+bytes", "why", "--addr", "0x1000", "--bytes", B, refuses="no-range"),
        c("function.discover+bytes", "function", "discover", "--bytes", B, "--start", "0x1000"),
        c("mem.read+bytes", "mem", "read", "--addr", "0x1", "--size", "4", "--bytes", B),
        c("strings+bytes", "strings", "--bytes", "41 42 43 44 45 46 00", refuses="no-range"),
        c("xref.from+bytes", "xref", "from", "--addr", "0x1000", "--bytes", B, refuses="no-range"),
        c("rtti.scan+bytes", "rtti", "scan", "--bytes", B, refuses="no-image-base"),
        c("diff.functions", "diff", "functions", "--a-file", A, "--a-addr", code, "--b-file", A, "--b-addr", hex(app["magic"])),
        c("diff.functions+bytes", "diff", "functions", "--a-bytes", B, "--a-addr", "0x0", "--b-bytes", B, "--b-addr", "0x0"),
        c("diff.functions+cross", "diff", "functions", "--a-file", A, "--a-addr", hex(app["magic"]), "--b-file", I + "app.elf", "--b-addr", hex(T["elf"]["magic"])),
        c("bundle.list", "bundle", "list", "--file", I + "test.bundle", must=["1111222233334444", "5555666677778888"]),
        c("bundle.list+type", "bundle", "list", "--file", I + "test.bundle", "--type", "lua"),
        c("bundle.extract", "bundle", "extract", "--file", I + "test.bundle", "--type", "lua", "--out", "{W}extracted"),
        c("bundle.extract+default", "bundle", "extract", "--file", I + "test.bundle", "--type", "lua", ignore=("out_path",)),
        c("bundle.repack", "bundle", "repack", "--file", I + "test.bundle", "--path-hash", "0x1111222233334444", "--replacement-file", I + "repl.bin", "--out", "{W}repacked.bundle"),
        c("bundle.list+repacked", "bundle", "list", "--file", "{W}repacked.bundle"),
        c("bundle+garbage", "bundle", "list", "--file", I + "payload.txt", refuses="bundle-load-failed"),
        c("lua.disasm", "lua", "disasm", "--file", I + "lj20.ljbc", must=["kstr", "1664525"]),
        c("lua.disasm+v2", "lua", "disasm", "--file", I + "lj21.ljbc", refuses="lua-disasm-failed"),
        c("lua.disasm+src", "lua", "disasm", "--file", I + "src.lua", refuses="lua-disasm-failed"),
        c("lua.patch", "lua", "patch", "--file", I + "lj20.ljbc", "--proto", "0", "--instr", "1", "--raw", "0x00000125", "--out", "{W}patched.ljbc"),
        c("lua.disasm+patched", "lua", "disasm", "--file", "{W}patched.ljbc"),
        c("const.identify+value", "const", "identify", "--value", "0x5bd1e995", must=["MurmurHash2"]),
        c("const.identify+float", "const", "identify", "--value", "2.3283064e-10"),
        c("const.identify+lua", "const", "identify", "--lua", I + "lj20.ljbc"),
        c("const.identify+luasrc", "const", "identify", "--lua", I + "src.lua", refuses="lua-disasm-failed"),
        c("concept.grep", "concept", "grep", "retry,backoff,timeout", "--dir", I + "scripts", must=["net.lua"]),
        c("concept.grep+term", "concept", "grep", "retry", "--dir", I + "scripts", "--term", "backoff", "--min-distinct", "2"),
        c("sig.validate+samples", "sig", "validate", "--sample", "48 8b 05 aa bb 48", "--sample", "48 8b 05 11 22 48", "--sample", "48 8b 05 33 44 48", "--signature", "48 8B 05 ?? ?? 48", "--varied", "input,session,seed", must=["48 8b 05 ?? ?? 48"]),
        c("sig.validate+files", "sig", "validate", "--sample-file", I + "sample1.bin", "--sample-file", I + "sample2.bin", "--sample-file", I + "sample3.bin", "--varied", "input,session,seed"),
        c("sig.gen+window", "sig", "gen", "--file", A, "--window", "16"),
        c("il2cpp.import", "il2cpp", "import", "--script-json", I + "script.json", "--name", "idx", "--file", A, "--force", ignore=("bytes_written",)),
        c("il2cpp.symbols", "il2cpp", "symbols", "--name", "idx", "--limit", "10"),
        c("il2cpp.symbols+query", "il2cpp", "symbols", "--name", "idx", "--query", "Tick", must=["Tick"]),
        c("il2cpp.metadata", "il2cpp", "metadata", "--metadata", I + "global-metadata.dat", "--limit", "10", must=["Alpha", "Ютф8", "Gamma"]),
        c("il2cpp.metadata+query", "il2cpp", "metadata", "--metadata", I + "global-metadata.dat", "--query", "Ютф", must=["Ютф8"]),
        c("serve", "serve", "--file", A, stdin=f'decomp pseudo --addr {hex(app["magic"])}\n["annotate","comment","--addr","{hex(app["magic"])}","--value","з \\"лапками\\""]\nmem read --addr {data} --size 8\nno such\nfunction discover --limit 5\n'),
        c("serve+nofile", "serve", "--file", I + "no_such.exe", stdin="doctor\n"),
        c("remote-serve+badpid", "remote-serve", "--pid", "999999", stdin=""),
        c("err.missing", "imports", "--file", I + "no_such.exe", refuses="load-failed"),
        c("err.dir", "imports", "--file", I + "scripts", refuses="load-failed", kind_only=True),
        c("err.badaddr", "disasm", "--addr", "zzz", "--file", A, refuses="bad-addr"),
        c("err.nosub", "scan", refuses="bad-arguments"),
        c("err.nocmd", "nonsense", refuses="bad-arguments"),
        c("err.noarg", "mem", "read", refuses="bad-arguments"),
        c("err.outside", "mem", "read", "--addr", "0x1", "--size", "4", "--file", A, refuses="read-failed"),
        c("err.garbage.profile", "profile", "--file", I + "payload.txt", refuses="load-failed"),
        c("err.garbage.discover", "function", "discover", "--file", I + "payload.txt", refuses="load-failed"),
        c("err.truncated", "profile", "--file", I + "truncated.exe", refuses="load-failed"),
        c("err.truncated.discover", "function", "discover", "--file", I + "truncated.exe", refuses="load-failed"),
        c("err.empty", "profile", "--file", I + "empty.bin", refuses="load-failed"),
    ]


# The refusals of the per-input list, by kind, then by the case's leading name and the inputs it refuses on. Anything not here
# must answer. An input only reads as refused when it is one the command has no business with: no code to lift (`wasm`), no
# exception directory, no runtime of that sort.
NATIVE = ("where", "version", "app", "strip", "dll", "pe32", "elf", "so", "arm64")
EVERY = (*NATIVE, "wasm")
REFUSALS = {
    "aot-failed": {"aot.symbols": EVERY},
    "no-index": {"il2cpp.symbols": EVERY},
    "no-metadata": {"il2cpp.metadata": EVERY},
    "no-rdata": {"il2cpp.icalls": ("elf", "so", "arm64", "wasm")},
    "klass-failed": {"il2cpp.obj": NATIVE},
    "no-native-pointers": {"il2cpp.obj": ("wasm",), "rtti.scan": ("wasm",)},
    "not-a-variable": {"annotate.var": NATIVE, "annotate.vartype": NATIVE},
    "not-checked": {"annotate.var": ("wasm",), "annotate.vartype": ("wasm",)},
    "no-range": {"strings+snapshot": NATIVE, "find+snapshot": NATIVE, "function.discover+snapshot": NATIVE},
    "discover-failed": {"function.discover+pdata": ("pe32", "elf", "so", "arm64", "wasm")},
    "no-exception-table": {"function.eh": ("wasm",)},
    "unsupported": {"snapshot.dump": ("wasm",)},
    "snapshot-load-failed": {x: ("wasm",) for x in ("snapshot.info", "mem.read+snapshot", "strings+snapshot", "find+snapshot", "function.discover+snapshot")},
    "not-lifted": {x: ("wasm",) for x in ("ir.build", "ir.explain", "ir.dot", "ir.value-set", "ir.deobfuscate", "ir.slice", "ir.manifest", "function.trace", "function.noreturn", "function.summary", "function.typeflow", "function.layout", "decomp.pseudo", "decomp.pseudo+goto", "decomp.pseudo+explain", "decomp.pseudo+after-annotate", "xref.string", "analyze", "bindings.list", "const.identify", "sig.gen")},
}


def refused(id, target):
    leaf = id.rsplit("__", 1)[0]
    for kind, leaves in REFUSALS.items():
        if target in leaves.get(leaf, ()):
            return kind
    return None


def all_static(T):
    return stateful(T)[:1] + per_input(T) + stateful(T)[1:]
