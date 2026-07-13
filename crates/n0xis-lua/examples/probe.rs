//! Ad hoc probe: `cargo run -p n0xis-lua --example probe -- <dir-of-.luac-files>`
//! Disassembles every file, reports parse success/failure counts, and prints
//! the first N instructions of a handful of chunks for manual sanity-checking.
//! Throwaway verification tool, not part of the public API.
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    let dir = args.get(1).expect("usage: probe <dir>");
    let mut ok = 0usize;
    let mut err = 0usize;
    let mut errors: Vec<(String, String)> = Vec::new();
    let mut sample_shown = 0usize;
    let show_samples: usize = args.get(2).map(|s| s.parse().unwrap_or(0)).unwrap_or(0);

    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("luac") {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        match n0xis_lua::disassemble(&bytes) {
            Ok(chunk) => {
                ok += 1;
                if sample_shown < show_samples {
                    sample_shown += 1;
                    println!("=== {} ===", path.display());
                    println!("protos={} stripped={}", chunk.protos.len(), chunk.stripped);
                    if let Some(top) = chunk.protos.last() {
                        println!("top-level proto: {} instrs, {} gc-consts, {} num-consts", top.instructions.len(), top.gc_constants.len(), top.num_constants.len());
                        for ins in top.instructions.iter().take(25) {
                            println!("  [{:3}] {}", ins.idx, ins.text);
                        }
                        let strings: Vec<String> = top
                            .gc_constants
                            .iter()
                            .filter_map(|c| if let n0xis_lua::GcConst::Str(s) = c { Some(s.clone()) } else { None })
                            .collect();
                        println!("  strings: {:?}", strings);
                    }
                }
            }
            Err(e) => {
                err += 1;
                errors.push((path.display().to_string(), e.to_string()));
            }
        }
    }
    println!("\nSUMMARY: ok={ok} err={err}");
    for (p, e) in errors.iter().take(20) {
        println!("  ERR {p}: {e}");
    }
}
