//! Ad hoc: patch the real firearm ammo component's `infinite_mags` check
//! (proto#6, instr idx=129: `TGETS r9, r8, "infinite_mags"` -> `KPRI r9, true`)
//! so the reload code always takes the "skip the num_mags decrement" branch.
//! Throwaway verification tool, not part of the public API.
use std::fs;

fn main() {
    let path = std::env::temp_dir().join("hd1_lua").join("672e9efb76793b9d.luac");
    let original = fs::read(&path).unwrap();
    let chunk = n0xis_lua::disassemble(&original).unwrap();

    let proto_idx = 6;
    let instr_idx = 129u32;
    println!("before: {}", chunk.protos[proto_idx].instructions[instr_idx as usize].text);
    assert_eq!(chunk.protos[proto_idx].instructions[instr_idx as usize].op, "TGETS");

    let kpri_op = n0xis_lua::OPCODES.iter().position(|o| o.name == "KPRI").unwrap() as u32;
    let a: u32 = 9; // r9, same destination register the original TGETS wrote
    let d: u32 = 2; // pri tag 2 = true
    let new_raw = kpri_op | (a << 8) | (d << 16);

    let patched = n0xis_lua::patch_instruction(&original, proto_idx, instr_idx, new_raw).unwrap();
    assert_eq!(patched.len(), original.len());
    let diffs = original.iter().zip(&patched).filter(|(a, b)| a != b).count();
    println!("bytes changed: {diffs} (out of {} total)", original.len());

    let repatched = n0xis_lua::disassemble(&patched).unwrap();
    let ins = &repatched.protos[proto_idx].instructions[instr_idx as usize];
    println!("after:  {}", ins.text);
    assert_eq!(ins.op, "KPRI");
    assert_eq!(ins.text, "KPRI r9, true");

    // Confirm the following IST/JMP pair (the actual branch) still decodes
    // identically -- only the value fed into the test changed, not the
    // control-flow instructions themselves.
    println!("next 3 instrs after patch: ");
    for k in instr_idx..instr_idx + 4 {
        println!("  [{k}] {}", repatched.protos[proto_idx].instructions[k as usize].text);
    }

    let out_dir = std::env::temp_dir().join("hd1_lua_patched");
    fs::create_dir_all(&out_dir).unwrap();
    let out_path = out_dir.join("672e9efb76793b9d.patched.luac");
    fs::write(&out_path, &patched).unwrap();
    println!("wrote patched chunk to {}", out_path.display());
}
