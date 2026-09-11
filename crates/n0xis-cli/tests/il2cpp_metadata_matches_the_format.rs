// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The IL2CPP metadata reader, against the format's own header.**
//!
//! This layer was recorded as unmeasured for one reason only — no IL2CPP target
//! on the machine. That stopped being true, so the entry stops being a refusal
//! and becomes a number.
//!
//! The outside source is rung 2: the producer's own artifact. `global-metadata.dat`
//! opens with a sanity word and a run of `(offset, size)` int32 pairs, one per
//! table, and the string literals are `(length, data_index)` pairs into a data
//! blob. Reading those bytes is unpacking a documented struct, not forming an
//! opinion — and the check that the unpacking is right is built in: a wrong
//! offset decodes the literals as noise, and these decode as text.
//!
//! Four independent things are compared, because the count agreeing while the
//! contents are garbage is exactly the shape a wrong answer takes here:
//!
//! 1. the format version and the table the header points at;
//! 2. the number of string literals the table's size implies;
//! 3. the literal **values**, byte for byte, against the bytes at those offsets;
//! 4. a text query's match count, recomputed from the same bytes.
//!
//! Plus the structural invariants a wrong layout cannot satisfy: tables
//! ascending, non-overlapping, and inside the file.
//!
//! **No target, no silence.** With no metadata blob to be found the test says so
//! on stderr and checks nothing, the same way the oracle corpus skips a shape
//! whose compiler is missing. Point it somewhere with `N0XIS_IL2CPP_ROOTS`
//! (`:`-separated directories to scan).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn n0xis_exe() -> PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

/// Directories to look under. An explicit list wins; otherwise the conventional
/// install roots, which is what makes this run without configuration on a
/// machine that happens to have a target and skip cleanly on one that does not.
fn roots() -> Vec<PathBuf> {
    if let Ok(list) = std::env::var("N0XIS_IL2CPP_ROOTS") {
        return list.split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect();
    }
    let mut out = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        for tail in [".steam/steam/steamapps/common", ".local/share/Steam/steamapps/common"] {
            out.push(Path::new(&home).join(tail));
        }
    }
    // Removable and secondary drives, one level down — a large library rarely
    // lives on the system disk.
    for base in ["/run/media", "/media", "/mnt"] {
        let Ok(users) = std::fs::read_dir(base) else { continue };
        for user in users.flatten() {
            let Ok(drives) = std::fs::read_dir(user.path()) else { continue };
            for drive in drives.flatten() {
                out.push(drive.path().join("SteamLibrary/steamapps/common"));
                out.push(drive.path().join("steamapps/common"));
            }
        }
    }
    out
}

/// Every `*_Data/il2cpp_data/Metadata/global-metadata.dat` under the roots.
/// Bounded to the depth the layout actually uses, so this never becomes a
/// filesystem walk.
fn find_metadata() -> Vec<PathBuf> {
    let mut found = Vec::new();
    for root in roots() {
        let Ok(games) = std::fs::read_dir(&root) else { continue };
        for game in games.flatten() {
            let Ok(entries) = std::fs::read_dir(game.path()) else { continue };
            for e in entries.flatten() {
                let p = e.path().join("il2cpp_data/Metadata/global-metadata.dat");
                if p.is_file() {
                    found.push(p);
                }
            }
        }
    }
    found.sort();
    found
}

/// The header, read straight from the bytes.
///
/// `sanity` and `version` are the first two words of every published version of
/// this struct; the `(offset, size)` pairs follow. Only the two the literals
/// need are named — those sit at the same place in every version this has been
/// run against, and the decoded text is the proof they were read right.
struct Header {
    version: i32,
    literal_off: usize,
    literal_size: usize,
    literal_data_off: usize,
}

fn read_header(bytes: &[u8]) -> Header {
    let i32_at = |o: usize| i32::from_le_bytes(bytes[o..o + 4].try_into().expect("4 bytes"));
    let sanity = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
    assert_eq!(sanity, 0xfab1_1baf, "not a global-metadata.dat");
    Header {
        version: i32_at(4),
        literal_off: i32_at(8) as usize,
        literal_size: i32_at(12) as usize,
        literal_data_off: i32_at(16) as usize,
    }
}

/// Every string literal, as the header's own tables lay them out.
fn literals(bytes: &[u8], h: &Header) -> Vec<Vec<u8>> {
    (0..h.literal_size / 8)
        .map(|i| {
            let e = h.literal_off + i * 8;
            let len = u32::from_le_bytes(bytes[e..e + 4].try_into().expect("4 bytes")) as usize;
            let idx = i32::from_le_bytes(bytes[e + 4..e + 8].try_into().expect("4 bytes")) as usize;
            let start = h.literal_data_off + idx;
            bytes[start..start + len].to_vec()
        })
        .collect()
}

fn run(args: &[&str]) -> Value {
    let out = Command::new(n0xis_exe()).args(args).output().expect("n0xis runs");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("not JSON: {e}\nstdout: {}", String::from_utf8_lossy(&out.stdout))
    })
}

#[test]
fn the_metadata_reader_reproduces_the_files_own_header() {
    let targets = find_metadata();
    if targets.is_empty() {
        eprintln!(
            "skip: no global-metadata.dat under {:?} — nothing was checked. \
             Set N0XIS_IL2CPP_ROOTS to a directory holding an IL2CPP build.",
            roots().len()
        );
        return;
    }

    let mut versions = Vec::new();
    for path in &targets {
        let bytes = std::fs::read(path).expect("readable metadata");
        let h = read_header(&bytes);
        let mine = literals(&bytes, &h);
        // A wrong offset decodes as noise. Text is what says the offsets were
        // read right, and it is checked rather than assumed.
        let text = mine.iter().filter(|l| !l.is_empty() && l.iter().all(|c| (32..127).contains(c))).count();
        assert!(
            text * 2 > mine.len(),
            "{}: only {text} of {} literals decode as text — the header was read wrongly, \
             and every comparison below would be against noise",
            path.display(),
            mine.len()
        );

        let p = path.to_string_lossy().to_string();
        let d = run(&["il2cpp", "metadata", "--metadata", &p, "--quiet", "--limit", "1000"]);
        assert!(d["ok"].as_bool() == Some(true), "{}: {d}", path.display());
        let d = &d["data"];

        assert_eq!(d["version"].as_i64(), Some(i64::from(h.version)), "format version");
        assert_eq!(
            d["literals_total"].as_u64(),
            Some(mine.len() as u64),
            "{}: literal count",
            path.display()
        );

        // The values, not just how many. A count that agrees while the contents
        // are noise is exactly the shape a wrong answer takes here.
        let got = d["literals"].as_array().expect("literals");
        assert!(!got.is_empty(), "no literals returned");
        for e in got {
            let i = e["index"].as_u64().expect("index") as usize;
            let want = String::from_utf8_lossy(&mine[i]).to_string();
            assert_eq!(e["value"].as_str(), Some(want.as_str()), "{}: literal {i}", path.display());
        }

        // A query is answered from the same bytes, so its count is checkable.
        let needle = "e";
        let q = run(&["il2cpp", "metadata", "--metadata", &p, "--quiet", "--query", needle, "--limit", "1"]);
        let want = mine
            .iter()
            .filter(|l| String::from_utf8_lossy(l).to_lowercase().contains(needle))
            .count();
        assert_eq!(
            q["data"]["matched"].as_u64(),
            Some(want as u64),
            "{}: matches for {needle:?}",
            path.display()
        );

        // Structural invariants a wrong table layout cannot satisfy.
        let file_len = bytes.len() as u64;
        let mut tables: Vec<(u64, u64, String)> = d["tables"]
            .as_array()
            .expect("tables")
            .iter()
            .map(|t| {
                (
                    t["offset"].as_u64().expect("offset"),
                    t["size"].as_u64().expect("size"),
                    t["name"].as_str().unwrap_or("?").to_string(),
                )
            })
            .collect();
        tables.sort();
        let mut end = 0u64;
        for (off, size, name) in &tables {
            assert!(*off >= end, "{}: table {name} overlaps the one before it", path.display());
            assert!(off + size <= file_len, "{}: table {name} runs past the file", path.display());
            end = off + size;
        }

        eprintln!(
            "{}: format version {}, {} literals, {} tables — all four agree with the header",
            path.file_name().unwrap_or_default().to_string_lossy(),
            h.version,
            mine.len(),
            tables.len()
        );
        versions.push(h.version);
    }

    versions.sort_unstable();
    versions.dedup();
    eprintln!("checked {} target(s), format version(s) {versions:?}", targets.len());
}
