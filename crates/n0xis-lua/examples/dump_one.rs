// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::fs;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let name = args.get(1).expect("usage: dump_one <filename.luac> [grep]");
    let grep = args.get(2).cloned();
    let path = std::env::temp_dir().join("hd1_lua").join(name);
    let bytes = fs::read(&path).unwrap();
    let chunk = n0xis_lua::disassemble(&bytes).unwrap();
    println!("protos: {}", chunk.protos.len());
    for (pidx, proto) in chunk.protos.iter().enumerate() {
        let mut lines = Vec::new();
        lines.push(format!("--- proto#{pidx} (params={}, frame={}, vararg={}, instrs={}) ---", proto.numparams, proto.framesize, proto.is_vararg, proto.instructions.len()));
        for ins in &proto.instructions {
            lines.push(format!("  [{:4}] {}", ins.idx, ins.text));
        }
        let joined = lines.join("\n");
        if let Some(g) = &grep {
            if joined.to_lowercase().contains(&g.to_lowercase()) {
                println!("{joined}");
            }
        } else {
            println!("{joined}");
        }
    }
}
