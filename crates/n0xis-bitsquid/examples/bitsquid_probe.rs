// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Ad hoc probe: `cargo run -p n0xis-bitsquid --example probe -- <bundle-file> [<bundle-file>.stream]`
//! Prints entry/type/variant summary. Throwaway verification tool, not part of the public API.
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).expect("usage: probe <bundle-file> [<stream-file>]");
    let bytes = fs::read(path).expect("read bundle file");
    let stream_path = args.get(2).cloned().unwrap_or_else(|| format!("{path}.stream"));
    let stream = fs::read(&stream_path).ok();
    println!("bundle: {path} ({} bytes), stream: {} ({} bytes)", bytes.len(), stream_path, stream.as_ref().map(|s| s.len()).unwrap_or(0));

    match n0xis_bitsquid::decompress_archive(&bytes) {
        Ok(decompressed) => {
            println!("decompressed: {} bytes", decompressed.len());
            match n0xis_bitsquid::parse_exploded_package(&decompressed, stream.as_deref()) {
                Ok(pkg) => {
                    println!("entries: {}", pkg.entries.len());
                    let mut by_type: std::collections::BTreeMap<String, usize> = Default::default();
                    for e in &pkg.entries {
                        let name = e.type_name.map(|s| s.to_string()).unwrap_or_else(|| format!("unknown:{:016x}", e.type_hash));
                        *by_type.entry(name).or_default() += 1;
                    }
                    for (ty, count) in &by_type {
                        println!("  {ty}: {count}");
                    }
                    let dump_dir = args.get(3).cloned();
                    for e in pkg.entries.iter().filter(|e| e.type_name == Some("lua")) {
                        for v in &e.variants {
                            if let Some(lr) = n0xis_bitsquid::lua_resource(v) {
                                if let Some(dir) = &dump_dir {
                                    fs::create_dir_all(dir).ok();
                                    let out = format!("{dir}/{:016x}.luac", e.path_hash);
                                    fs::write(&out, &lr.data).ok();
                                } else {
                                    println!(
                                        "LUA path_hash={:016x} format={:?} data_len={}",
                                        e.path_hash, lr.format, lr.data.len()
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => println!("parse_exploded_package error: {e}"),
            }
        }
        Err(e) => println!("decompress_archive error: {e}"),
    }
}
