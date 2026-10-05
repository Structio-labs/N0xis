// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Every section of every ELF file on this machine reads as the file holds
//! it.** A local instrument, not a CI gate (`--features oracle`): it walks the
//! system's own ELF files, so its inputs are whatever this machine has.
//!
//! The section table comes from `readelf -SW` (binutils), not from this crate,
//! and the expected bytes are the file's own at the offsets readelf gives. A
//! section the image maps but reads wrongly — shadowed by another, cut short,
//! taken from the wrong offset — shows up here as a mismatch.
//!
//! Written for the `.tbss` shadowing found 2026-10-05; on the system it was
//! found on it reported 568 files with sections read wrongly before the fix.
//! `N0X_ELF_SWEEP_LIMIT` bounds how many files are read (default 2000).
#![cfg(feature = "oracle")]
#![cfg(all(feature = "static-pe", target_os = "linux"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use n0xis_contracts::Va;
use n0xis_sources::{MemorySource, StaticElf};

/// Files above this size are skipped: the comparison copies each section.
const MAX_FILE: u64 = 64 << 20;
const SHT_NOBITS: &str = "NOBITS";

struct Section {
    name: String,
    kind: String,
    addr: u64,
    offset: usize,
    size: usize,
}

/// The allocated sections `readelf -SW` lists for `path`.
fn readelf_sections(path: &Path) -> Option<Vec<Section>> {
    let out = Command::new("readelf").arg("-SW").arg(path).env("LC_ALL", "C").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut sections = Vec::new();
    for line in text.lines() {
        // `  [Nr] Name Type Address Off Size ...`; the bracket may hold a space.
        let Some(rest) = line.trim_start().strip_prefix('[') else { continue };
        let Some((_, rest)) = rest.split_once(']') else { continue };
        let f: Vec<&str> = rest.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let (Ok(addr), Ok(offset), Ok(size)) =
            (u64::from_str_radix(f[2], 16), usize::from_str_radix(f[3], 16), usize::from_str_radix(f[4], 16))
        else {
            continue;
        };
        if addr == 0 || size == 0 {
            continue;
        }
        sections.push(Section { name: f[0].to_string(), kind: f[1].to_string(), addr, offset, size });
    }
    Some(sections)
}

fn elf_files(roots: &[&str], limit: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() && meta.len() <= MAX_FILE {
                let mut magic = [0u8; 4];
                let is_elf = std::fs::File::open(&path)
                    .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic))
                    .is_ok_and(|()| magic == *b"\x7fELF");
                if is_elf {
                    out.push(path);
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
        }
    }
    out
}

#[test]
fn every_section_reads_as_the_file_holds_it() {
    if Command::new("readelf").arg("--version").output().is_err() {
        eprintln!("SKIPPED: no readelf");
        return;
    }
    let limit = std::env::var("N0X_ELF_SWEEP_LIMIT").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
    let files = elf_files(&["/usr/bin", "/usr/lib"], limit);
    let (mut checked_files, mut checked_sections) = (0usize, 0usize);
    let mut wrong: Vec<String> = Vec::new();
    for path in &files {
        let Some(sections) = readelf_sections(path) else { continue };
        let Ok(elf) = StaticElf::load(path) else { continue };
        let Ok(file) = std::fs::read(path) else { continue };
        checked_files += 1;
        for s in sections.iter().filter(|s| s.kind != SHT_NOBITS) {
            let Some(expected) = file.get(s.offset..s.offset + s.size) else { continue };
            checked_sections += 1;
            match elf.read(Va(s.addr), s.size) {
                Ok(got) if got == expected => {}
                Ok(got) => wrong.push(format!(
                    "{} {} at {:#x}: read {} of {} bytes, {}",
                    path.display(),
                    s.name,
                    s.addr,
                    got.len(),
                    s.size,
                    if got.len() == s.size { "different bytes" } else { "short" }
                )),
                Err(e) => wrong.push(format!("{} {} at {:#x}: {e}", path.display(), s.name, s.addr)),
            }
        }
    }
    eprintln!("{checked_files} files, {checked_sections} file-backed sections compared; {} read wrongly", wrong.len());
    assert!(checked_sections > 0, "nothing was compared, so nothing was shown");
    assert!(wrong.is_empty(), "{} sections read wrongly; the first:\n{}", wrong.len(), wrong.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}
