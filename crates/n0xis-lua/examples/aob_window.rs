//! Ad hoc: print the raw byte window (as an AOB hex pattern) around a given
//! instruction, for use as a live memory-scan pattern. Throwaway tool.
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = &args[1];
    let proto_idx: usize = args[2].parse().unwrap();
    let center_instr: u32 = args[3].parse().unwrap();
    let before: u32 = args.get(4).map(|s| s.parse().unwrap()).unwrap_or(5);
    let after: u32 = args.get(5).map(|s| s.parse().unwrap()).unwrap_or(5);

    let bytes = fs::read(path).unwrap();
    let chunk = n0xis_lua::disassemble(&bytes).unwrap();
    let proto = &chunk.protos[proto_idx];
    let offset = proto.bytecode_file_offset;
    println!("proto#{proto_idx} bytecode_file_offset = {offset} (0x{offset:x})");

    let start_instr = center_instr.saturating_sub(before).max(1);
    let end_instr = (center_instr + after + 1).min(proto.instructions.len() as u32);

    println!("\nInstruction window [{start_instr}, {end_instr}):");
    for i in start_instr..end_instr {
        let ins = &proto.instructions[i as usize];
        let marker = if i == center_instr { " <== TARGET" } else { "" };
        println!("  [{i:4}] raw=0x{:08x}  {}{marker}", ins.raw, ins.text);
    }

    let byte_start = offset + (start_instr as usize - 1) * 4;
    let byte_end = offset + (end_instr as usize - 1) * 4;
    let window = &bytes[byte_start..byte_end];
    println!("\nAbsolute file byte range: [{byte_start}, {byte_end}) ({} bytes)", window.len());
    let hex: Vec<String> = window.iter().map(|b| format!("{b:02x}")).collect();
    println!("AOB pattern (n0xis scan aob --pattern):\n{}", hex.join(" "));

    let target_byte_offset = offset + (center_instr as usize - 1) * 4;
    println!("\nTarget instruction's own absolute byte offset in this file: {target_byte_offset} (0x{target_byte_offset:x})");
    println!("Its offset within the AOB window above: {}", target_byte_offset - byte_start);
}
