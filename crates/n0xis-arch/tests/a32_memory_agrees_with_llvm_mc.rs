// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Every load, store, block transfer and `pc`-reading form `arm32.rs`
//! lifts, judged word by word against an independent disassembler.**
//!
//! The lift reads the decoder's operands; a lifted word is a claim that the
//! word *is* the instruction those operands describe. So every word of the
//! spaces below that n0xis lifts — anything but `asm` — goes to `llvm-mc
//! --disassemble`, and four columns are counted:
//!
//! * `llvm-mc` prints the **same instruction** (the texts agree after
//!   [`canon`], which removes only spelling: `#`, number bases, `ip` for
//!   `r12`);
//! * `llvm-mc` **rejects** the word — n0xis lifted an instruction that does
//!   not exist;
//! * `llvm-mc` accepts it with "potentially undefined instruction encoding" —
//!   n0xis lifted a word whose register choice the architecture leaves
//!   UNPREDICTABLE, which has no value to state;
//! * the texts **differ** — the decoder read other operands than the word has.
//!
//! The last three must be zero. Words n0xis keeps as `asm` are counted and not
//! judged: a refusal is not a claim. `llvm-mc` does not flag every
//! UNPREDICTABLE choice (it accepts `ldrd r0, r1, [r2, r0]`, which the ARM ARM
//! makes UNPREDICTABLE), so the third column is a floor, not a proof.
//!
//! The spaces: A32 word/byte with immediate and register index, the "extra"
//! halfword/signed/dual forms, block transfers and `adr`, at `AL` and `NE`,
//! stratified over the register fields ([`NIBBLES`]); every 16-bit Thumb
//! halfword; and the 32-bit Thumb load/store and block-transfer first
//! halfwords, each against a spread of second halfwords. Thumb words are
//! limited to the families this lift claims (`ldr*`/`str*`/`ldm*`/`stm*`/
//! `push`/`pop`/`adr`, and any lifted text that names `pc`).
//!
//! Needs `llvm-mc` (or `$LLVM_MC`), so it is not part of CI:
//!
//! ```text
//! cargo test -p n0xis-arch --release --test a32_memory_agrees_with_llvm_mc -- --ignored --nocapture
//! ```

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::process::Command;

use n0xis_arch::{Arch, Arm32, MicroStmt};
use n0xis_contracts::Va;

/// Register-field values that meet every special case: `r0`, `r1`, a middle
/// register, `sp`, `lr`, `pc`.
const NIBBLES: [u32; 6] = [0, 1, 5, 13, 14, 15];

const CONDS: [u32; 2] = [0b1110, 0b0001];

/// A32 word/byte load/store, immediate offset: `cond 010 PUBWL Rn Rt imm12`.
fn a32_word_byte_imm() -> Vec<u32> {
    let mut out = Vec::new();
    for cond in CONDS {
        for op in 0..32 {
            for rn in NIBBLES {
                for rt in NIBBLES {
                    for imm in [0u32, 1, 4, 0x18c, 0xfff] {
                        out.push(cond << 28 | 0b010 << 25 | op << 20 | rn << 16 | rt << 12 | imm);
                    }
                }
            }
        }
    }
    out
}

/// A32 word/byte load/store, (shifted-)register offset: `cond 011 PUBWL Rn Rt
/// imm5 type 0 Rm`, the shifts including `lsr #32` (amount 0) and `rrx`.
fn a32_word_byte_reg() -> Vec<u32> {
    let mut out = Vec::new();
    for cond in CONDS {
        for op in 0..32 {
            for rn in NIBBLES {
                for rt in NIBBLES {
                    for (imm5, ty) in [(0u32, 0u32), (2, 0), (0, 1), (1, 2), (0, 3), (4, 3)] {
                        for rm in [0u32, 2, 15] {
                            out.push(cond << 28 | 0b011 << 25 | op << 20 | rn << 16 | rt << 12 | imm5 << 7 | ty << 5 | rm);
                        }
                    }
                }
            }
        }
    }
    out
}

/// A32 "extra" load/store — `ldrh`/`strh`/`ldrsb`/`ldrsh`/`ldrd`/`strd`:
/// `cond 000 PUIWL Rn Rt hi 1 op2 1 lo`. With `I` clear `hi` should be zero
/// and `lo` is `Rm`; both values of `hi` are tried.
fn a32_extra() -> Vec<u32> {
    let mut out = Vec::new();
    for cond in CONDS {
        for op in 0..32u32 {
            let imm = op & 0b00100 != 0;
            let fields: &[(u32, u32)] = if imm { &[(0, 0), (1, 2), (0xf, 0xf)] } else { &[(0, 0), (0, 2), (0, 15), (0xf, 0), (0xf, 2), (0xf, 15)] };
            for op2 in [0b01u32, 0b10, 0b11] {
                for rn in NIBBLES {
                    for rt in NIBBLES {
                        for &(hi, lo) in fields {
                            out.push(cond << 28 | op << 20 | rn << 16 | rt << 12 | hi << 8 | 1 << 7 | op2 << 5 | 1 << 4 | lo);
                        }
                    }
                }
            }
        }
    }
    out
}

/// A32 block transfers: `cond 100 PUSWL Rn list`.
fn a32_block() -> Vec<u32> {
    let mut out = Vec::new();
    for cond in CONDS {
        for op in 0..32 {
            for rn in NIBBLES {
                for list in [0x0000u32, 0x0001, 0x0003, 0x0006, 0x2002, 0x4010, 0x8000, 0x8002, 0xffff] {
                    out.push(cond << 28 | 0b100 << 25 | op << 20 | rn << 16 | list);
                }
            }
        }
    }
    out
}

/// A32 `add`/`sub` (immediate) with `Rn = pc` — `adr`, and its flag-setting
/// neighbours.
fn a32_adr() -> Vec<u32> {
    let mut out = Vec::new();
    for cond in CONDS {
        for opcode in [0b0100u32, 0b0010] {
            for s in 0..2 {
                for rd in NIBBLES {
                    for imm in [0u32, 0x10, 0x4ff] {
                        out.push(cond << 28 | 0b001 << 25 | opcode << 21 | s << 20 | 0xf << 16 | rd << 12 | imm);
                    }
                }
            }
        }
    }
    out
}

/// One encoding space and its instruction set.
struct Space {
    name: &'static str,
    thumb: bool,
    words: fn() -> Vec<Vec<u8>>,
}

fn le32(words: Vec<u32>) -> Vec<Vec<u8>> {
    words.into_iter().map(|w| w.to_le_bytes().to_vec()).collect()
}

const SPACES: &[Space] = &[
    Space { name: "A32 word/byte, immediate", thumb: false, words: || le32(a32_word_byte_imm()) },
    Space { name: "A32 word/byte, register", thumb: false, words: || le32(a32_word_byte_reg()) },
    Space { name: "A32 halfword/signed/dual", thumb: false, words: || le32(a32_extra()) },
    Space { name: "A32 ldm/stm", thumb: false, words: || le32(a32_block()) },
    Space { name: "A32 adr", thumb: false, words: || le32(a32_adr()) },
    Space {
        name: "Thumb 16-bit, every halfword",
        thumb: true,
        words: || (0..=0xffffu32).filter(|h| h >> 11 < 0b11101).map(|h| (h as u16).to_le_bytes().to_vec()).collect(),
    },
    Space {
        name: "Thumb 32-bit load/store/ldm/stm/adr",
        thumb: true,
        words: || {
            let firsts = (0xe800u32..=0xe9ff).chain(0xf800..=0xf9ff).chain([0xf20f, 0xf2af]);
            let mut out = Vec::new();
            for hw1 in firsts {
                for rt in NIBBLES {
                    for mid in [0x0u32, 0x8, 0x9, 0xb, 0xc, 0xd, 0xe, 0xf] {
                        for low in [0x00u32, 0x04, 0x22, 0xff] {
                            let hw2 = rt << 12 | mid << 8 | low;
                            let mut b = (hw1 as u16).to_le_bytes().to_vec();
                            b.extend((hw2 as u16).to_le_bytes());
                            out.push(b);
                        }
                    }
                }
            }
            out
        },
    },
];

/// One lifted word: its bytes and n0xis's text.
struct Lifted {
    bytes: Vec<u8>,
    text: String,
}

/// Does n0xis lift this word (anything but `asm`), and in a family this
/// instrument judges? Its text when it does.
fn lifted(arch: &Arm32, thumb: bool, bytes: &[u8]) -> Option<String> {
    let di = arch.decode(bytes, Va(0x1000)).ok()?;
    if di.len as usize != bytes.len() {
        return None;
    }
    let stmts = arch.lift(&di, "aapcs32");
    if stmts.is_empty() || stmts.iter().any(|s| matches!(s, MicroStmt::Unlifted { .. })) {
        return None;
    }
    let m = di.mnemonic.as_str();
    // Branches name `pc` too (`blx pc`), and are not this lift's.
    let branch = m.starts_with('b') || m.starts_with("cb");
    let family = ["ldr", "str", "ldm", "stm", "push", "pop", "adr"].iter().any(|p| m.starts_with(p)) || (di.text.contains("pc") && !branch);
    // A32 data processing reading `pc` is the crate's decode, unchanged by
    // this lift; only `adr` is judged there (its sign was the decoder's error).
    let family = family && (thumb || !di.text.contains("pc") || ["ldr", "str", "ldm", "stm", "push", "pop", "adr", "sub"].iter().any(|p| m.starts_with(p)));
    family.then_some(di.text)
}

/// What `llvm-mc` made of one word.
#[derive(Clone, Debug, PartialEq)]
enum Reference {
    Rejected,
    Unpredictable(String),
    Accepted(String),
}

/// `llvm-mc --disassemble -show-encoding` over `words`, one per line. Each
/// accepted word is paired with the printed instruction whose encoding is its
/// bytes — not by position, because a rejected 32-bit Thumb word makes the
/// disassembler resynchronise inside the next line. A word whose answer is not
/// found is asked again alone.
fn llvm_mc(words: &[Vec<u8>], thumb: bool) -> Vec<Reference> {
    let exe = std::env::var("LLVM_MC").unwrap_or_else(|_| "llvm-mc".to_string());
    let triple = if thumb { "thumbv7-none-eabi" } else { "armv6-none-eabi" };
    let path = std::env::temp_dir().join(format!("n0xis-a32-memory-{}-{}.txt", std::process::id(), words.len()));
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path).expect("temp file"));
        for w in words {
            let line: Vec<String> = w.iter().map(|b| format!("0x{b:02x}")).collect();
            writeln!(f, "{}", line.join(" ")).expect("write");
        }
    }
    let out = Command::new(&exe)
        .args(["--disassemble", "-show-encoding", &format!("-triple={triple}")])
        .arg(&path)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {exe} ({e}); this test needs llvm-mc"));
    let _ = std::fs::remove_file(&path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let (mut rejected, mut unpredictable) = (HashSet::new(), HashSet::new());
    for line in stderr.lines().filter(|l| l.contains(": warning: ") || l.contains(": error: ")) {
        let (at, what) = line.rsplit_once(": warning: ").unwrap_or_else(|| panic!("a diagnostic this harness does not know: {line}"));
        let mut parts = at.rsplit(':');
        let col: usize = parts.next().and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("unparsed diagnostic: {line}"));
        let line_no: usize = parts.next().and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("unparsed diagnostic: {line}"));
        if col != 1 {
            continue; // a resynchronisation inside a line already judged
        }
        match what {
            "invalid instruction encoding" => rejected.insert(line_no - 1),
            "potentially undefined instruction encoding" => unpredictable.insert(line_no - 1),
            _ => panic!("a diagnostic this harness does not know: {line}"),
        };
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let printed: Vec<(Vec<u8>, String)> = stdout
        .lines()
        .filter(|l| l.starts_with('\t') && !l.starts_with("\t."))
        .filter_map(|l| {
            let (text, enc) = l.split_once("@ encoding: [")?;
            let bytes = enc.trim_end_matches(']').split(',').map(|b| u8::from_str_radix(b.trim().trim_start_matches("0x"), 16).ok()).collect::<Option<Vec<u8>>>()?;
            Some((bytes, text.trim().to_string()))
        })
        .collect();
    let mut at = 0usize;
    let mut result = Vec::with_capacity(words.len());
    for (i, w) in words.iter().enumerate() {
        if rejected.contains(&i) {
            result.push(Reference::Rejected);
            continue;
        }
        match printed[at.min(printed.len())..].iter().take(8).position(|(b, _)| b == w) {
            Some(k) => {
                let text = printed[at + k].1.clone();
                at += k + 1;
                result.push(if unpredictable.contains(&i) { Reference::Unpredictable(text) } else { Reference::Accepted(text) });
            }
            None if words.len() > 1 => result.push(llvm_mc(std::slice::from_ref(w), thumb).remove(0)),
            // Asked alone, one word and one printed instruction pair by
            // position: llvm-mc prints the canonical encoding, which differs
            // from the input where a should-be field was set the other way.
            None if printed.len() == 1 => {
                let text = printed[0].1.clone();
                result.push(if unpredictable.contains(&i) { Reference::Unpredictable(text) } else { Reference::Accepted(text) });
            }
            None => panic!("llvm-mc printed {} instructions for {w:02x?} and did not reject it", printed.len()),
        }
    }
    result
}

/// The spelling-free form of an instruction's text: `#` dropped, every number
/// in decimal, `ip`/`fp`/`sl`/`sb` as `r12`/`r11`/`r10`/`r9`, no width
/// qualifier, no whitespace.
/// Two texts that agree here name the same operation on the same operands.
fn canon(s: &str) -> String {
    let s = s.to_lowercase().replace('#', "");
    let mut out = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let neg_number = c == '-' && chars.get(i + 1).is_some_and(|d| d.is_ascii_digit());
        if c.is_ascii_digit() || neg_number {
            let start = if neg_number { i + 1 } else { i };
            let (radix, digits_at) = if chars.get(start) == Some(&'0') && chars.get(start + 1) == Some(&'x') { (16, start + 2) } else { (10, start) };
            let mut j = digits_at;
            while j < chars.len() && chars[j].is_digit(radix) {
                j += 1;
            }
            let digits: String = chars[digits_at..j].iter().collect();
            let value = i64::from_str_radix(&digits, radix).unwrap_or(0);
            out += &format!("{}{value}", if neg_number { "-" } else { "" });
            i = j;
        } else if c.is_ascii_alphabetic() {
            let mut j = i;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '.') {
                j += 1;
            }
            let word: String = chars[i..j].iter().collect();
            // A width qualifier (`.w`, `.n`) names the encoding's size, which
            // the bytes already fix; it is spelling.
            let word = word.trim_end_matches(".w").trim_end_matches(".n");
            out += match word {
                "ip" => "r12",
                "fp" => "r11",
                "sl" => "r10",
                "sb" => "r9",
                w => w,
            };
            i = j;
        } else {
            if !c.is_whitespace() {
                out.push(c);
            }
            i += 1;
        }
    }
    out
}

/// A text difference that is spelling the two disassemblers choose
/// differently, each with its reason. A difference outside these fails.
struct Known {
    class: &'static str,
    holds: fn(&str, &str) -> bool,
}

const KNOWN: &[Known] = &[
    // A32 `adr` (the adding form): the decoder prints `adr r0, pc, 0x10`;
    // llvm-mc's disassembler the base instruction, `add r0, pc, #16` — and a
    // rotated immediate with bit 31 set as a negative number
    // (`#-16777216` for 0xff000000).
    Known {
        class: "adr spelled as add",
        holds: |n, l| {
            let n = n.replacen("adr", "add", 1);
            n == l || n == last_number_as_u32(l)
        },
    },
    // Thumb's 32-bit `adr` (`addw`/`subw rd, pc, #imm`): the decoder prints
    // the base instruction (`add r0, pc, 0x4`), llvm-mc the alias (`adr.w r0,
    // #4`, and `adr.w r0, #-4` for the subtracting form) — or, for a zero
    // subtracted, the encoding's own name (`subw r0, pc, #0`).
    Known {
        class: "thumb adr.w spelled as add/sub",
        holds: |n, l| {
            if let Some(rest) = l.strip_prefix("subw").or_else(|| l.strip_prefix("addw")) {
                return n == format!("{}{rest}", &l[..3]);
            }
            let Some(rest) = l.strip_prefix("adr") else { return false };
            let Some((rd, imm)) = rest.split_once(',') else { return false };
            match imm.strip_prefix('-') {
                Some(neg) => n == format!("sub{rd},pc,{neg}"),
                None => n == format!("add{rd},pc,{imm}"),
            }
        },
    },
    // A32 `pop`/`push` of one register in the block-transfer encoding: the
    // decoder prints the alias, llvm-mc `ldm sp!, {r0}` / `stmdb sp!, {r0}`
    // (the ARM ARM: `POP` with fewer than two registers is "SEE LDM").
    Known {
        class: "one-register block push/pop alias",
        holds: |n, l| {
            (n.starts_with("pop{") && l.starts_with("ldmsp!,{") && n[3..] == l[7..]) || (n.starts_with("push{") && l.starts_with("stmdbsp!,{") && n[4..] == l[9..])
        },
    },
    // A subtracted zero offset: llvm-mc keeps the sign (`[r1, #-0]`), the
    // decoder drops the operand (`[r1]`). The address is the same.
    Known { class: "minus zero offset", holds: |n, l| l.replace(",-0]", "]") == n },
    // A zero offset: llvm-mc prints `[pc, #0]` for Thumb's literal load, the
    // decoder `[pc]`. The same address.
    Known { class: "zero offset", holds: |n, l| l.replace(",0]", "]") == n },
    // `ia` is the default block-transfer mode and UAL leaves it unspelled:
    // the decoder prints Thumb's 16-bit `stmia r0!, {r1}`, llvm-mc `stm r0!,
    // {r1}`. (The decoder's A32 `ldmia` for an increment-before word, which
    // this cannot hide, prints `ldmib` now; `ldmia` against `ldmib` still
    // differs here.)
    Known { class: "ia spelled", holds: |n, l| n.replacen("stmia", "stm", 1) == l || n.replacen("ldmia", "ldm", 1) == l },
    // A zero offset with write-back: llvm-mc prints `[r0, #0]!`, the decoder
    // `[r0]!`. The address and the written-back base are both `r0`.
    Known { class: "zero offset with write-back", holds: |n, l| l.replace(",0]!", "]!").replace(",-0]!", "]!") == n },
    // The single-register `push`/`pop` (ARM ARM: `STR`/`LDR` encoding A2 —
    // `str rt, [sp, #-4]!`, `ldr rt, [sp], #4`). The decoder prints the alias;
    // llvm-mc's disassembler the base form (its assembler prints the alias).
    Known {
        class: "single-register push/pop alias",
        holds: |n, l| {
            let alias = |r: &str| (l == format!("ldr{r},[sp],4") && n == format!("pop{{{r}}}")) || (l == format!("str{r},[sp,-4]!") && n == format!("push{{{r}}}"));
            ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "pc"].iter().any(|r| alias(r))
        },
    },
];

/// Whether n0xis's text and llvm-mc's name one instruction: `Some(None)` when
/// they agree after [`canon`], `Some(Some(class))` when they differ only by a
/// [`KNOWN`] spelling, `None` when they differ.
fn same_instruction(n0xis: &str, llvm: &str) -> Option<Option<&'static str>> {
    let (n, l) = (canon(n0xis), canon(llvm));
    if n == l {
        return Some(None);
    }
    KNOWN.iter().find(|k| (k.holds)(&n, &l)).map(|k| Some(k.class))
}

/// `s` with its last number, when negative, read as the 32-bit word it is.
fn last_number_as_u32(s: &str) -> String {
    let Some(at) = s.rfind('-') else { return s.to_string() };
    match s[at + 1..].parse::<i64>() {
        Ok(v) => format!("{}{}", &s[..at], (-v) as u32),
        Err(_) => s.to_string(),
    }
}

/// llvm-mc's "potentially undefined" that the ARM ARM does not support, each
/// with its reason and the processor's answer.
struct KnownWarning {
    class: &'static str,
    holds: fn(bool, &[u8]) -> bool,
}

const KNOWN_WARNINGS: &[KnownWarning] = &[
    // A32 `strd` (immediate) whose low immediate nibble is 1111 — the field
    // that is `Rm` in the register form, where 1111 is UNPREDICTABLE. llvm-mc
    // warns on `strd` (not on `ldrd`); the ARM ARM's STRD (immediate) has no
    // such condition, and `n0xis-core/tests/a32_memory_agrees_with_the_
    // processor.rs` (`strd_imm4l_f`) runs one through the processor, which
    // stores it.
    KnownWarning {
        class: "strd imm4L = 1111",
        holds: |thumb, b| {
            let Some(w) = b.first_chunk::<4>().map(|w| u32::from_le_bytes(*w)).filter(|_| !thumb) else { return false };
            w & 0x0e40_00f0 == 0x0040_00f0 && w & (1 << 20) == 0 && w & 0xf == 0xf
        },
    },
    // Thumb `ldrd`/`strd` pre-indexed with write-back on `sp` (`strd r0, r8,
    // [sp, #-16]!`, the shape a compiler's paired push takes). The ARM ARM's
    // T1 encoding makes `n == 15`, `t`/`t2` in {13, 15} and write-back into a
    // transferred register UNPREDICTABLE, not `n == 13`; the processor oracle
    // runs both (`t_strd_sp_wb`, `t_ldrd_sp_wb`) and agrees with the lift.
    KnownWarning {
        class: "thumb ldrd/strd [sp, #imm]!",
        holds: |thumb, b| {
            let Some(hw1) = b.first_chunk::<2>().map(|h| u16::from_le_bytes(*h)).filter(|_| thumb && b.len() == 4) else { return false };
            hw1 & 0xfe40 == 0xe840 && hw1 & (1 << 8) != 0 && hw1 & (1 << 5) != 0 && hw1 & 0xf == 13
        },
    },
];

#[derive(Default)]
struct Tally {
    words: u64,
    lifted: u64,
    agree: u64,
    known: BTreeMap<&'static str, u64>,
    rejected: Vec<String>,
    unpredictable: Vec<String>,
    differs: Vec<String>,
    by_mnemonic: BTreeMap<String, u64>,
}

#[test]
#[ignore = "needs llvm-mc; run by hand when the A32 lift or decoder changes"]
fn every_lifted_memory_form_is_the_instruction_llvm_mc_reads() {
    // `N0XIS_SPACE=<substring>` measures only the spaces whose name holds it;
    // `N0XIS_SHOW=<n>` prints up to n disagreements of each kind (12).
    let only = std::env::var("N0XIS_SPACE").ok();
    let show_n = std::env::var("N0XIS_SHOW").ok().and_then(|s| s.parse().ok()).unwrap_or(12);
    let mut failed = false;
    for space in SPACES.iter().filter(|s| only.as_deref().is_none_or(|o| s.name.contains(o))) {
        let arch = if space.thumb { Arm32::thumb() } else { Arm32::a32() };
        let words = (space.words)();
        let mut t = Tally { words: words.len() as u64, ..Tally::default() };
        let claims: Vec<Lifted> = words.into_iter().filter_map(|bytes| lifted(&arch, space.thumb, &bytes).map(|text| Lifted { bytes, text })).collect();
        t.lifted = claims.len() as u64;
        let references: Vec<Reference> = claims.chunks(20_000).flat_map(|c| llvm_mc(&c.iter().map(|l| l.bytes.clone()).collect::<Vec<_>>(), space.thumb)).collect();
        for (claim, reference) in claims.iter().zip(references) {
            let mnemonic = claim.text.split_whitespace().next().unwrap_or("").to_string();
            *t.by_mnemonic.entry(mnemonic).or_default() += 1;
            let show = |l: &str| format!("{:02x?}: n0xis `{}`, llvm-mc `{l}`", claim.bytes, claim.text);
            match reference {
                Reference::Rejected => t.rejected.push(show("(invalid encoding)")),
                Reference::Unpredictable(l) => match KNOWN_WARNINGS.iter().find(|k| (k.holds)(space.thumb, &claim.bytes)) {
                    Some(k) if same_instruction(&claim.text, &l).is_some() => *t.known.entry(k.class).or_default() += 1,
                    _ => t.unpredictable.push(show(&l)),
                },
                Reference::Accepted(l) => match same_instruction(&claim.text, &l) {
                    Some(None) => t.agree += 1,
                    Some(Some(class)) => *t.known.entry(class).or_default() += 1,
                    None => t.differs.push(show(&l)),
                },
            }
        }
        eprintln!(
            "{}: {} words, {} lifted -> {} agree, {:?} known spelling, {} rejected by llvm-mc, {} potentially undefined, {} differ",
            space.name,
            t.words,
            t.lifted,
            t.agree,
            t.known,
            t.rejected.len(),
            t.unpredictable.len(),
            t.differs.len()
        );
        eprintln!("    lifted mnemonics: {:?}", t.by_mnemonic);
        for (what, list) in [("REJECTED", &t.rejected), ("UNPREDICTABLE", &t.unpredictable), ("DIFFERS", &t.differs)] {
            for e in list.iter().take(show_n) {
                eprintln!("    {what} {e}");
            }
        }
        failed |= !(t.rejected.is_empty() && t.unpredictable.is_empty() && t.differs.is_empty());
        assert!(t.lifted > 0, "{}: nothing was lifted — the instrument judged nothing", space.name);
    }
    assert!(!failed, "a lifted word is not the instruction llvm-mc reads; see above");
}
