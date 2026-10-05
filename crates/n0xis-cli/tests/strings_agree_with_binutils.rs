// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`strings` against binutils `strings`**, on the system's own images, in
//! both encodings. A local instrument (`--features oracle`): its inputs are
//! whatever this machine has.
//!
//! The two agree on what an ASCII character is (tab and 0x20–0x7e); this tool
//! also keeps line breaks in a string, where binutils, one string to a line,
//! cuts there, and it reads characters past ASCII as part of a string, where
//! binutils' UTF-16 (`-e l`) reads only ASCII ones. So, within each section the
//! tool read (the section table from `readelf -SW`):
//! - every string binutils finds there lies inside one of the tool's, byte for
//!   byte (it may be a piece of a longer one);
//! - every string of the tool's that is pure ASCII, cut at its line breaks, is
//!   pieces each of which is exactly one of binutils', at its address (a piece
//!   shorter than four characters is not one of binutils' and is passed over).
//!
//! Left out, and counted: a binutils string that runs across a section edge
//! (the tool reads sections apart), and a UTF-16 string at an odd address
//! (the tool reads UTF-16 at even addresses only).
//!
//! The two checks above say nothing about strings past ASCII, which binutils
//! does not read. Where binary data reads as text there, the count is what
//! shows it: with every printable character allowed in UTF-16 the tool found
//! 10 625 UTF-16 strings in a library where binutils found 11. So the count of
//! the tool's strings is held to a bound over binutils', per image and
//! encoding.
#![cfg(feature = "oracle")]
#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("n0xis")
}

#[derive(Clone, Copy)]
enum Encoding {
    Utf8,
    Utf16le,
}

impl Encoding {
    fn ours(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Utf16le => "utf16le",
        }
    }
    fn binutils(self) -> &'static str {
        match self {
            Self::Utf8 => "s",
            Self::Utf16le => "l",
        }
    }
    /// The bytes `text` takes in the image.
    fn bytes(self, text: &str) -> Vec<u8> {
        match self {
            Self::Utf8 => text.as_bytes().to_vec(),
            Self::Utf16le => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        }
    }
}

/// `(name, address, file offset, size)` of each section, from `readelf -SW`.
fn sections(path: &Path) -> Vec<(String, u64, u64, u64)> {
    let out = Command::new("readelf").arg("-SW").arg(path).env("LC_ALL", "C").output().expect("readelf");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix('[')?.split_once(']')?.1;
            let f: Vec<&str> = rest.split_whitespace().collect();
            let hex = |s: &str| u64::from_str_radix(s, 16).ok();
            Some((f.first()?.to_string(), hex(f.get(2)?)?, hex(f.get(3)?)?, hex(f.get(4)?)?))
        })
        .collect()
}

/// binutils' strings of at least `min` characters: file offset → text, which
/// is ASCII in both encodings.
fn binutils_strings(path: &Path, encoding: Encoding, min: usize) -> BTreeMap<u64, String> {
    let out = Command::new("strings")
        .args(["-a", "-e", encoding.binutils(), "-t", "x", "-n", &min.to_string()])
        .arg(path)
        .output()
        .expect("strings");
    let mut found = BTreeMap::new();
    // One string per line: neither tool takes a line break for a character.
    for line in out.stdout.split(|&b| b == b'\n') {
        let line: Vec<u8> = line.iter().copied().skip_while(|&b| b == b' ').collect();
        let Some(space) = line.iter().position(|&b| b == b' ') else { continue };
        let Ok(offset) = u64::from_str_radix(std::str::from_utf8(&line[..space]).unwrap_or(""), 16) else { continue };
        found.insert(offset, String::from_utf8_lossy(&line[space + 1..]).into_owned());
    }
    found
}

#[derive(Default)]
struct Tally {
    compared: usize,
    ours: usize,
    crossing: usize,
    odd: usize,
    wrong: Vec<String>,
}

fn compare(path: &Path, cwd: &Path, encoding: Encoding) -> Tally {
    let out = Command::new(n0xis_exe())
        .current_dir(cwd)
        .args(["strings", "--encoding", encoding.ours(), "--limit", "0", "--file"])
        .arg(path)
        .output()
        .expect("run n0xis");
    let v: Value = serde_json::from_slice(&out.stdout).expect("one envelope");
    assert_eq!(v["ok"], true, "{}: {v}", path.display());
    let read: BTreeSet<String> = v["data"]["ranges"].as_array().unwrap().iter().filter_map(|r| r["name"].as_str().map(String::from)).collect();
    let ours: Vec<(u64, String)> = v["data"]["strings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (u64::from_str_radix(s["address"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap(), s["text"].as_str().unwrap().to_string()))
        .collect();
    let file_sections: Vec<_> = sections(path).into_iter().filter(|(name, addr, _, _)| *addr != 0 && read.contains(name)).collect();
    let mut tally = Tally { ours: ours.len(), ..Tally::default() };
    let mut theirs_by_va: BTreeMap<u64, String> = BTreeMap::new();
    // Where a binutils string crosses a section edge, the tool's string there
    // is a piece of it, so it is not held to match.
    let mut excused: Vec<(u64, u64)> = Vec::new();
    for (offset, text) in binutils_strings(path, encoding, 4) {
        let end = offset + encoding.bytes(&text).len() as u64;
        let mut inside = None;
        for (name, addr, off, size) in &file_sections {
            if offset >= *off && end <= off + size {
                inside = Some((name.clone(), *addr, *off));
            } else if offset < off + size && end > *off {
                tally.crossing += 1;
                let from = offset.max(*off);
                excused.push((addr + (from - off), addr + (end.min(off + size) - off)));
            }
        }
        let Some((name, addr, off)) = inside else { continue };
        let va = addr + (offset - off);
        if matches!(encoding, Encoding::Utf16le) && va % 2 == 1 {
            tally.odd += 1;
            continue;
        }
        tally.compared += 1;
        let want = encoding.bytes(&text);
        let covered = ours.iter().any(|(start, s)| {
            let bytes = encoding.bytes(s);
            va >= *start && va + want.len() as u64 <= start + bytes.len() as u64 && bytes[(va - start) as usize..][..want.len()] == want[..]
        });
        if !covered {
            tally.wrong.push(format!("{} {name} {va:#x}: binutils {text:?} is in none of ours", path.display()));
        }
        theirs_by_va.insert(va, text);
    }
    let width = if matches!(encoding, Encoding::Utf16le) { 2 } else { 1 };
    for (start, text) in &ours {
        if !text.is_ascii() {
            continue;
        }
        let mut at = *start;
        for piece in text.split(['\n', '\r']) {
            let here = at;
            at += (piece.len() as u64 + 1) * width;
            if piece.len() < 4 || excused.iter().any(|(from, to)| here >= *from && here < *to) {
                continue;
            }
            if theirs_by_va.get(&here).map(String::as_str) != Some(piece) {
                tally.wrong.push(format!("{} {here:#x}: ours {piece:?}, binutils {:?}", path.display(), theirs_by_va.get(&here)));
            }
        }
    }
    tally
}

#[test]
fn strings_agree_with_binutils_on_the_systems_images() {
    if Command::new("strings").arg("--version").output().is_err() || !n0xis_exe().exists() {
        eprintln!("SKIPPED: no binutils strings, or no n0xis binary");
        return;
    }
    let cwd = std::env::temp_dir().join(format!("n0xis-strings-oracle-{}", std::process::id()));
    std::fs::create_dir_all(cwd.join(".n0x")).expect("temp project");
    let targets: Vec<PathBuf> = ["/usr/bin/ls", "/usr/lib/libz.so.1", "/usr/lib/libstdc++.so.6", "/usr/bin/python3"]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    assert!(!targets.is_empty(), "no target found, so nothing would be shown");
    let mut all_wrong = Vec::new();
    let mut compared = 0;
    for t in &targets {
        let path = std::fs::canonicalize(t).expect("path");
        for encoding in [Encoding::Utf8, Encoding::Utf16le] {
            let t = compare(&path, &cwd, encoding);
            eprintln!(
                "{} {}: {} binutils strings compared, {} of ours, {} across a section edge and {} at an odd address left out, {} wrong",
                path.display(),
                encoding.ours(),
                t.compared,
                t.ours,
                t.crossing,
                t.odd,
                t.wrong.len()
            );
            compared += t.compared;
            all_wrong.extend(t.wrong);
            // Past ASCII the tool finds more than binutils by design; this much
            // more is binary data read as text.
            let bound = t.compared * 3 / 2 + 100;
            if t.ours > bound {
                all_wrong.push(format!("{} {}: {} strings of ours against {} of binutils, over the bound of {bound}", path.display(), encoding.ours(), t.ours, t.compared));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&cwd);
    assert!(compared > 0, "nothing was compared, so nothing was shown");
    assert!(all_wrong.is_empty(), "{} disagreements; the first:\n{}", all_wrong.len(), all_wrong.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}
