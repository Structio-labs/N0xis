// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The A32 encoding spaces `arm32.rs` decodes itself, judged word by word
//! against an independent disassembler.**
//!
//! `yaxpeax-arm` 0.5.0 returns an error for the whole A32 *media* class
//! (`cond != 1111`, bits 27-25 = `011`, bit 4 = 1) — `uxtb`, `sxth`, `rev16`,
//! `ubfx`, `pkhbt`, the parallel add/sub family — and misreads part of the
//! halfword multiplies, so `arm32/own.rs` decodes both spaces. A decoder
//! written here is the thing under test, so its answer is checked against
//! `llvm-mc --disassemble`, never against itself: every word of each space
//! below goes to both, and five columns are counted:
//!
//! * both accept, and the **text is identical** (the decoder prints UAL, the
//!   assembler syntax `llvm-mc` prints, `r9`/`r11`/`r12` included);
//! * both accept, and the text differs in a way recorded in [`KNOWN`] — where
//!   `llvm-mc` prints something the encoding does not say;
//! * both reject;
//! * only n0xis accepts — an invented instruction;
//! * only `llvm-mc` accepts — a real instruction shown as `(bad)`, which also
//!   stops a linear sweep and cuts a function's CFG;
//!
//! and any other text difference fails. `llvm-mc` accepts a word it warns is
//! "potentially undefined" (an UNPREDICTABLE register choice or a should-be
//! field set the other way); that counts as accepted, because it prints the
//! instruction.
//!
//! The reference is `-triple=armv7ve-none-eabi`. Over these spaces it differs
//! from `armv7-none-eabi` only by `sdiv`/`udiv` (the ARMv7 divide extension,
//! which every ARMv8 AArch32 processor has, and which the crate already decodes
//! in Thumb). Set `N0XIS_LLVM_TRIPLE` to measure against another.
//!
//! Needs `llvm-mc` (or `$LLVM_MC`), so it is not part of CI. Run it whenever the
//! A32 decoder changes — about seventy seconds in release:
//!
//! ```text
//! cargo test -p n0xis-arch --release --test a32_media_agrees_with_llvm_mc -- --ignored --nocapture
//! ```
//!
//! CI gates on the same answer without `llvm-mc`:
//! [`the_decoder_still_says_what_llvm_mc_was_shown`] recomputes a digest of
//! n0xis's text over every word of the stratified spaces and over the whole
//! halfword-multiply space, and pins the digest this instrument printed when it
//! last agreed. A decoder change moves the digest; then this instrument is run
//! again, and the digest is updated only if it agrees.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::process::Command;

use n0xis_arch::{Arch, Arm32};
use n0xis_contracts::Va;

/// The media class at one condition: `cond 011x xxxx xxxx xxxx xxxx xxx1 xxxx`.
fn media_word(cond: u32, free: u32) -> u32 {
    cond << 28 | 0b011 << 25 | (free >> 4) << 5 | 1 << 4 | (free & 0xf)
}

/// The halfword multiplies (`smul<x><y>`, `smla<x><y>`, `smulw<y>`,
/// `smlaw<y>`, `smlal<x><y>`): `cond 0001 0op0 xxxx xxxx xxxx 1yx0 xxxx`.
fn halfmul_word(cond: u32, free: u32) -> u32 {
    let op = (free >> 18) & 0b11;
    let regs = (free >> 6) & 0xfff; // bits 19-8
    let yx = (free >> 4) & 0b11; // bits 6-5
    cond << 28 | 0x0100_0080 | op << 21 | regs << 8 | yx << 5 | (free & 0xf)
}

/// Register-field values that meet every special case the encodings have: `0`,
/// `1111` (the "absent" register and the should-be-one fields) and a spread
/// between.
const NIBBLES: [u32; 6] = [0, 1, 5, 10, 14, 15];

/// Every opcode-field pattern of the media class (`op1` = bits 24-20, `op2` =
/// bits 7-5) against every combination of [`NIBBLES`] in the four other
/// nibbles, at one condition: 32 × 8 × 6^4 = 331 776 words.
fn media_stratified(cond: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for op1 in 0..32 {
        for op2 in 0..8 {
            for a in NIBBLES {
                for b in NIBBLES {
                    for c in NIBBLES {
                        for d in NIBBLES {
                            out.push(cond << 28 | 0b011 << 25 | op1 << 20 | a << 16 | b << 12 | c << 8 | op2 << 5 | 1 << 4 | d);
                        }
                    }
                }
            }
        }
    }
    out
}

/// The halfword multiplies at one condition, every opcode pattern against
/// [`NIBBLES`] in the four register fields: 4 × 4 × 6^4 = 20 736 words.
fn halfmul_stratified(cond: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for op in 0..4 {
        for yx in 0..4 {
            for a in NIBBLES {
                for b in NIBBLES {
                    for c in NIBBLES {
                        for d in NIBBLES {
                            out.push(cond << 28 | 0x0100_0080 | op << 21 | a << 16 | b << 12 | c << 8 | yx << 5 | d);
                        }
                    }
                }
            }
        }
    }
    out
}

/// One encoding space: a name and every word it holds, in a fixed order.
struct Space {
    name: &'static str,
    words: fn() -> Vec<u32>,
}

/// The spaces, at `AL` exhaustively and at every other condition stratified.
/// `cond = 1111` is the unconditional space, which neither owned class covers:
/// there the media decoder must claim nothing, and what the crate makes of
/// those words is recorded, not judged.
const SPACES: &[Space] = &[
    Space { name: "media, cond=AL, every word (2^24)", words: || (0..1u32 << 24).map(|f| media_word(0b1110, f)).collect() },
    Space { name: "media, cond=0000..1101, stratified", words: || (0..0b1110u32).flat_map(media_stratified).collect() },
    Space { name: "media pattern, cond=1111, stratified", words: || media_stratified(0b1111) },
    Space { name: "halfword multiply, cond=AL, every word (2^20)", words: || (0..1u32 << 20).map(|f| halfmul_word(0b1110, f)).collect() },
    Space { name: "halfword multiply, cond=0000..1101, stratified", words: || (0..0b1110u32).flat_map(halfmul_stratified).collect() },
    Space { name: "halfword multiply pattern, cond=1111, stratified", words: || halfmul_stratified(0b1111) },
];

/// What each space measured, `llvm-mc` 23.1.1, `armv7ve-none-eabi`. Every
/// column is pinned, the recorded ones as much as the zeros: a recorded
/// difference that disappears is a change too.
struct Expected {
    space: &'static str,
    both_accept: u64,
    known_text: u64,
    both_reject: u64,
    only_n0xis: u64,
    only_llvm: u64,
}

const EXPECTED: &[Expected] = &[
    Expected { space: "media, cond=AL, every word (2^24)", both_accept: 5_723_135, known_text: 126_977, both_reject: 10_927_104, only_n0xis: 0, only_llvm: 0 },
    Expected { space: "media, cond=0000..1101, stratified", both_accept: 1_576_008, known_text: 34_776, both_reject: 3_034_080, only_n0xis: 0, only_llvm: 0 },
    Expected { space: "media pattern, cond=1111, stratified", both_accept: 0, known_text: 0, both_reject: 331_776, only_n0xis: 0, only_llvm: 0 },
    Expected { space: "halfword multiply, cond=AL, every word (2^20)", both_accept: 1_048_576, known_text: 0, both_reject: 0, only_n0xis: 0, only_llvm: 0 },
    Expected { space: "halfword multiply, cond=0000..1101, stratified", both_accept: 290_304, known_text: 0, both_reject: 0, only_n0xis: 0, only_llvm: 0 },
    // Not an owned space: these are the crate's unconditional-space words
    // (`cps`, `cpsid`, `cpsie` with mode fields it refuses), recorded so a
    // change in them is seen, and outside what this decoder answers for.
    Expected { space: "halfword multiply pattern, cond=1111, stratified", both_accept: 0, known_text: 0, both_reject: 19_440, only_n0xis: 0, only_llvm: 1_296 },
];

/// A text difference that is the reference's: a name, and whether a word with
/// n0xis's and `llvm-mc`'s texts is one.
struct Known {
    class: &'static str,
    holds: fn(u32, &str, &str) -> bool,
}

/// The text differences that are the reference's, each with its reason. A
/// difference outside these fails the run.
const KNOWN: &[Known] = &[
    // `bfi`/`bfc` with `msb < lsb` (UNPREDICTABLE): llvm-mc prints `lsb`
    // replaced by `msb` and a width of 1, fields the word does not hold; n0xis
    // prints the two fields as they are, as GNU objdump does —
    // `(invalid: 17:16)`.
    Known {
        class: "bitfield with msb below lsb",
        holds: |w, n, l| {
            let (msb, lsb) = ((w >> 16) & 0x1f, (w >> 7) & 0x1f);
            let bf = w & 0x0fe0_0070 == 0x07c0_0010;
            bf && msb < lsb && n.contains(&format!("(invalid: {lsb}:{msb})")) && l.ends_with(&format!("#{msb}, #1"))
        },
    },
    // 0xe7ffdefe: llvm-mc's alias `trap` (the word its compiler emits for a
    // trap); the ARM ARM and GNU objdump: `udf #65006`.
    Known { class: "the trap alias", holds: |w, n, l| w == 0xe7ff_defe && n == "udf #65006" && l == "trap" },
];

/// What `llvm-mc` made of one batch of words: `None` for a rejected word, the
/// normalized text for an accepted one. A diagnostic this does not recognize,
/// or a count that does not add up, fails the run — a harness that misreads
/// its reference would otherwise report a clean table.
fn llvm_mc(words: &[u32], batch: usize) -> Vec<Option<String>> {
    let exe = std::env::var("LLVM_MC").unwrap_or_else(|_| "llvm-mc".to_string());
    let triple = std::env::var("N0XIS_LLVM_TRIPLE").unwrap_or_else(|_| "armv7ve-none-eabi".to_string());
    let path = std::env::temp_dir().join(format!("n0xis-a32-media-{}-{batch}.txt", std::process::id()));
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path).expect("temp file"));
        for w in words {
            let b = w.to_le_bytes();
            writeln!(f, "0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}", b[0], b[1], b[2], b[3]).expect("write");
        }
    }
    let out = Command::new(&exe)
        .args(["--disassemble", &format!("-triple={triple}")])
        .arg(&path)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {exe} ({e}); this test needs llvm-mc"));
    let _ = std::fs::remove_file(&path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let mut rejected = HashSet::new();
    for line in stderr.lines().filter(|l| l.contains("warning:") || l.contains("error:")) {
        // `<path>:<line>:<col>: warning: <what>`
        let (at, what) = line.rsplit_once(": warning: ").unwrap_or_else(|| panic!("a diagnostic this harness does not know: {line}"));
        let line_no: usize = at.rsplit(':').nth(1).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("unparsed diagnostic: {line}"));
        match what {
            "invalid instruction encoding" => {
                rejected.insert(line_no - 1);
            }
            "potentially undefined instruction encoding" => {}
            _ => panic!("a diagnostic this harness does not know: {line}"),
        }
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut texts = stdout.lines().filter(|l| l.starts_with('\t') && !l.starts_with("\t.")).map(normalize);
    let result: Vec<Option<String>> = (0..words.len()).map(|i| if rejected.contains(&i) { None } else { texts.next() }).collect();
    assert!(texts.next().is_none(), "llvm-mc printed more instructions than it accepted words");
    assert!(result.iter().enumerate().all(|(i, r)| r.is_some() || rejected.contains(&i)), "llvm-mc printed fewer instructions than it accepted words");
    result
}

/// `\tuxtb\tr8, r3, ror #8` → `uxtb r8, r3, ror #8`.
fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Default)]
struct Tally {
    both_accept: u64,
    known_text: u64,
    both_reject: u64,
    only_n0xis: u64,
    only_llvm: u64,
    text_differs: u64,
    examples: BTreeMap<&'static str, Vec<String>>,
    mnemonics: BTreeMap<String, u64>,
    /// The disagreeing words by class and mnemonic, so a nonzero column says
    /// which instruction it is about.
    by_mnemonic: BTreeMap<(&'static str, String), u64>,
}

impl Tally {
    fn example(&mut self, class: &'static str, mnemonic: &str, s: String) {
        *self.by_mnemonic.entry((class, mnemonic.to_string())).or_default() += 1;
        let v = self.examples.entry(class).or_default();
        if v.len() < 12 {
            v.push(s);
        }
    }
    fn merge(&mut self, o: Tally) {
        self.both_accept += o.both_accept;
        self.known_text += o.known_text;
        self.both_reject += o.both_reject;
        self.only_n0xis += o.only_n0xis;
        self.only_llvm += o.only_llvm;
        self.text_differs += o.text_differs;
        for (k, v) in o.examples {
            let e = self.examples.entry(k).or_default();
            e.extend(v.into_iter().take(12usize.saturating_sub(e.len())));
        }
        for (k, v) in o.mnemonics {
            *self.mnemonics.entry(k).or_default() += v;
        }
        for (k, v) in o.by_mnemonic {
            *self.by_mnemonic.entry(k).or_default() += v;
        }
    }
}

/// n0xis's text for a word, or `None` for a decode error — through the public
/// entry point, the one every command uses.
fn n0xis(arch: &Arm32, word: u32) -> Option<String> {
    arch.decode(&word.to_le_bytes(), Va(0x1000)).ok().map(|d| d.text)
}

fn first_word(s: &str) -> &str {
    s.split(' ').next().unwrap_or("")
}

fn compare(words: &[u32], batch: usize) -> Tally {
    let reference = llvm_mc(words, batch);
    let arch = Arm32::a32();
    let mut t = Tally::default();
    for (&w, r) in words.iter().zip(reference) {
        match (n0xis(&arch, w), r) {
            (Some(n), Some(l)) if n == l => {
                t.both_accept += 1;
                *t.mnemonics.entry(first_word(&l).to_string()).or_default() += 1;
            }
            (Some(n), Some(l)) => match KNOWN.iter().find(|k| (k.holds)(w, &n, &l)) {
                Some(k) => {
                    t.known_text += 1;
                    t.example(k.class, first_word(&n), format!("{w:08x}: n0xis `{n}`, llvm-mc `{l}`"));
                }
                None => {
                    t.text_differs += 1;
                    t.example("text differs", first_word(&n), format!("{w:08x}: n0xis `{n}`, llvm-mc `{l}`"));
                }
            },
            (None, None) => t.both_reject += 1,
            (Some(n), None) => {
                t.only_n0xis += 1;
                t.example("only n0xis accepts", first_word(&n), format!("{w:08x}: `{n}`"));
            }
            (None, Some(l)) => {
                t.only_llvm += 1;
                t.example("only llvm-mc accepts", first_word(&l), format!("{w:08x}: `{l}`"));
            }
        }
    }
    t
}

#[test]
#[ignore = "needs llvm-mc; an instrument to run by hand when the A32 decoder changes"]
fn a32_media_and_halfword_multiplies_agree_with_llvm_mc() {
    const BATCH: usize = 1 << 18;
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get()).min(4);
    let mut failures = Vec::new();
    for space in SPACES {
        let words = (space.words)();
        let batches: Vec<&[u32]> = words.chunks(BATCH).collect();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let total = std::thread::scope(|s| {
            let workers: Vec<_> = (0..threads)
                .map(|_| {
                    s.spawn(|| {
                        let mut t = Tally::default();
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(b) = batches.get(i) else { break t };
                            t.merge(compare(b, i));
                        }
                    })
                })
                .collect();
            workers.into_iter().fold(Tally::default(), |mut acc, w| {
                acc.merge(w.join().expect("worker"));
                acc
            })
        });
        eprintln!("\n== {} ({} words)", space.name, words.len());
        eprintln!(
            "   both accept {} | known text difference {} | both reject {} | only n0xis {} | only llvm-mc {} | text differs {}",
            total.both_accept, total.known_text, total.both_reject, total.only_n0xis, total.only_llvm, total.text_differs
        );
        eprintln!("   accepted mnemonics ({}): {:?}", total.mnemonics.len(), total.mnemonics);
        for ((class, mnemonic), n) in &total.by_mnemonic {
            eprintln!("   {class}: {mnemonic} x{n}");
        }
        for (class, ex) in &total.examples {
            eprintln!("   {class}:");
            for e in ex {
                eprintln!("     {e}");
            }
        }
        let counted = total.both_accept + total.known_text + total.both_reject + total.only_n0xis + total.only_llvm + total.text_differs;
        assert_eq!(counted, words.len() as u64, "every word is counted once");
        if total.text_differs != 0 {
            failures.push(format!("{}: {} text differences not recorded in KNOWN", space.name, total.text_differs));
        }
        let measured = (total.both_accept, total.known_text, total.both_reject, total.only_n0xis, total.only_llvm);
        match EXPECTED.iter().find(|e| e.space == space.name) {
            Some(e) if (e.both_accept, e.known_text, e.both_reject, e.only_n0xis, e.only_llvm) == measured => {}
            Some(e) => failures.push(format!(
                "{}: expected (accept, known text, reject, only n0xis, only llvm-mc) = {:?}, measured {measured:?}",
                space.name,
                (e.both_accept, e.known_text, e.both_reject, e.only_n0xis, e.only_llvm)
            )),
            None => failures.push(format!("{}: no recorded expectation", space.name)),
        }
    }
    eprintln!("\nCI digests (the_decoder_still_says_what_llvm_mc_was_shown):");
    for (name, words) in digest_sets() {
        eprintln!("   {name}: {:#018x}", digest(&words));
    }
    assert!(failures.is_empty(), "disagreements with llvm-mc:\n{}", failures.join("\n"));
}

/// FNV-1a over each word and n0xis's text for it (`(bad)` for an error).
fn digest(words: &[u32]) -> u64 {
    let arch = Arm32::a32();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &w in words {
        let text = n0xis(&arch, w).unwrap_or_else(|| "(bad)".to_string());
        for b in w.to_le_bytes().iter().chain(text.as_bytes()).chain(b"\n") {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

/// The word sets CI pins. All are subsets of what the instrument judges — the
/// stratified media space at all sixteen conditions, the whole halfword
/// multiply space at `AL` and the stratified one at the rest — so a digest
/// that still matches means the decoder still says, for each of these words,
/// what `llvm-mc` was shown.
fn digest_sets() -> Vec<(&'static str, Vec<u32>)> {
    vec![
        ("media, stratified, all 16 conditions", (0..16u32).flat_map(media_stratified).collect()),
        ("halfword multiply, every AL word and stratified at the rest", (0..1u32 << 20).map(|f| halfmul_word(0b1110, f)).chain((0..16u32).filter(|&c| c != 0b1110).flat_map(halfmul_stratified)).collect()),
    ]
}

/// **The CI gate on the instrument's answer.** No `llvm-mc` needed: the digest
/// of n0xis's text over [`digest_sets`] is what the instrument printed in the
/// run whose table [`EXPECTED`] records. If this fails, the decoder's answer
/// changed somewhere in those 6 668 032 words — run the instrument, and
/// update a digest only from a run that agrees.
#[test]
fn the_decoder_still_says_what_llvm_mc_was_shown() {
    const PINNED: &[(&str, u64)] = &[
        ("media, stratified, all 16 conditions", 0xe83f_781d_dc3d_5413),
        ("halfword multiply, every AL word and stratified at the rest", 0x26fd_96d8_ec92_8175),
    ];
    for (name, words) in digest_sets() {
        let measured = digest(&words);
        let pinned = PINNED.iter().find(|p| p.0 == name).map(|p| p.1);
        assert_eq!(pinned, Some(measured), "{name}: the decoder's text over {} words changed (digest {measured:#018x})", words.len());
    }
}
