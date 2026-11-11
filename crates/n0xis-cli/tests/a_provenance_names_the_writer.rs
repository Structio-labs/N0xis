// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`provenance trace` names the function and the instruction that wrote.** On an
//! unstripped PIE it said "no recovered function covers" the writer, which the symbol
//! table and `.eh_frame` both cover, and gave as `instruction_va` the instruction after
//! the write (audit 2026-11-06, row 9). The writer there was unaligned, right after a
//! function that ends in a `jmp`, and named only by an address handed to
//! `pthread_create`: no prologue rule, no `call` and no boundary finds it, and the
//! context the command built had none of what the image states.
//!
//! The same layout is fixed here in assembly, so no compiler decides it, and the target
//! prints where its writer and its writing instruction are: the oracle.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

use serde_json::Value;

mod support;

const TARGET_SRC: &str = r#"
use std::io::Write;
const PR_SET_PTRACER: i32 = 0x59616d61;
unsafe extern "C" {
    fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32;
    fn n0x_before();
    fn n0x_writer() -> !;
    static n0x_write_insn: u8;
}
#[unsafe(no_mangle)]
static mut N0X_CELL: u32 = 0;
std::arch::global_asm!(
    ".text",
    ".p2align 4",
    ".globl n0x_before",
    ".type n0x_before,@function",
    "n0x_before:",
    ".cfi_startproc",
    "nop",
    "jmp n0x_before",
    ".cfi_endproc",
    ".size n0x_before, .-n0x_before",
    ".globl n0x_writer",
    ".type n0x_writer,@function",
    "n0x_writer:",
    ".cfi_startproc",
    "sub rsp, 8",
    ".cfi_def_cfa_offset 16",
    "2:",
    ".globl n0x_write_insn",
    "n0x_write_insn:",
    "add dword ptr [rip + N0X_CELL], 1",
    "mov edi, 10000",
    "call usleep",
    "jmp 2b",
    ".cfi_endproc",
    ".size n0x_writer, .-n0x_writer",
);
fn main() {
    unsafe { prctl(PR_SET_PTRACER, u64::MAX, 0, 0, 0) };
    if std::env::args().count() > 99 { unsafe { n0x_before() } }
    // Named only by its address, as `pthread_create`'s argument names one.
    let writer = std::hint::black_box(n0x_writer as unsafe extern "C" fn() -> !);
    std::thread::spawn(move || unsafe { writer() });
    println!("{:#x} {:#x} {:#x}", &raw const N0X_CELL as usize, n0x_writer as usize, unsafe { &n0x_write_insn as *const u8 as usize });
    std::io::stdout().flush().unwrap();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
}
"#;

fn target_exe() -> &'static Path {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("n0xis-provenance-build-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("build dir");
        let src = dir.join("target.rs");
        let exe = dir.join("target");
        std::fs::write(&src, TARGET_SRC).expect("write the target");
        let out = Command::new("rustc").args(["-O", "--edition", "2024", "-o"]).arg(&exe).arg(&src).output().expect("invoke rustc");
        assert!(out.status.success(), "rustc failed on the target:\n{}", String::from_utf8_lossy(&out.stderr));
        exe
    })
}

struct Target(Child, PathBuf);

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap_or("").trim_start_matches("0x"), 16).unwrap_or_else(|_| panic!("not an address: {v}"))
}

#[test]
fn the_writer_an_unaligned_function_after_a_jmp_is_named_with_its_instruction() {
    let dir = std::env::temp_dir().join(format!("n0xis-provenance-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("a project of its own");
    let mut child = Command::new(target_exe()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("run the target");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let pid = child.id();
    let _target = Target(child, dir.clone());
    let mut line = String::new();
    stdout.read_line(&mut line).expect("the target's addresses");
    let a: Vec<u64> = line.split_whitespace().map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("an address")).collect();
    let (cell, writer, write_insn) = (a[0], a[1], a[2]);
    assert!(writer % 16 != 0, "the writer must be unaligned for this test to mean anything: {writer:#x}");

    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis")))
        .args(["provenance", "trace", "--pid", &pid.to_string(), "--addr", &format!("{cell:#x}"), "--kind", "write", "--len", "4", "--timeout-ms", "10000"])
        .current_dir(&dir)
        .output()
        .expect("run n0xis");
    let answer: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("no JSON: {}", String::from_utf8_lossy(&out.stderr)));
    let entry = &answer["data"]["entries"][0];
    assert!(entry.get("context_unavailable").is_none(), "{answer}");
    assert_eq!(hex(&entry["function_va"]), writer, "{answer}");
    assert_eq!(hex(&entry["instruction_va"]), write_insn, "the write, not the instruction after it: {answer}");
}
