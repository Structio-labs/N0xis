// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::fs;
fn main() {
    let dir = std::env::temp_dir().join("hd1_lua");
    let dir = dir.as_path();
    let mut hits: Vec<(String, Vec<String>)> = Vec::new();
    let keywords = ["ammo", "magazine", "reload", "clip_size", "mag_size", "reserve"];
    for entry in fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("luac") { continue; }
        let bytes = fs::read(&path).unwrap();
        if let Ok(chunk) = n0xis_lua::disassemble(&bytes) {
            let mut matched_strings = Vec::new();
            for proto in &chunk.protos {
                for c in &proto.gc_constants {
                    if let n0xis_lua::GcConst::Str(s) = c {
                        let lower = s.to_lowercase();
                        if keywords.iter().any(|k| lower.contains(k)) {
                            matched_strings.push(s.clone());
                        }
                    }
                }
            }
            if !matched_strings.is_empty() {
                matched_strings.sort();
                matched_strings.dedup();
                hits.push((path.file_name().unwrap().to_string_lossy().to_string(), matched_strings));
            }
        }
    }
    hits.sort_by_key(|(_, s)| std::cmp::Reverse(s.len()));
    for (name, strs) in &hits {
        println!("{name}: {strs:?}");
    }
    println!("\ntotal files with ammo-keywords: {}", hits.len());
}
