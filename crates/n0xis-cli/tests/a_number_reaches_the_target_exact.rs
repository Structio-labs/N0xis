// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **A number on its way to a target is the number written, or it is refused.**
//! `scan value --type u64 --value <past 2^53>` used to pass through `f64`: the
//! scanner looked for the double nearest the value and answered, with
//! `exhaustive:true`, that the target did not hold what it held, or that it held a
//! neighbour it was not asked for.
//!
//! The truth is planted here: integers a double cannot tell apart, written by this
//! test into a copy of a committed image at the place its section table states.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

mod support;

const IMAGE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/strings_planted.so");
const TWO_53: u64 = 1 << 53;
/// In the planted order: three that one double covers, and two past `i64::MAX`.
const PLANTED: [u64; 5] = [TWO_53, TWO_53 + 1, TWO_53 + 2, u64::MAX - 2, 0xDEAD_BEEF_CAFE_F00D];

struct Fixture {
    dir: PathBuf,
    image: String,
    addr: u64,
}

fn fixture(name: &str) -> Fixture {
    let mut file = std::fs::read(IMAGE).expect("read the fixture");
    let (addr, offset) = {
        let elf = goblin::elf::Elf::parse(&file).expect("an ELF");
        let s = elf.section_headers.iter().find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".rodata")).expect("a .rodata");
        assert!(s.sh_size as usize >= PLANTED.len() * 8, "the fixture's .rodata has to hold the plant");
        (s.sh_addr, s.sh_offset as usize)
    };
    for (i, v) in PLANTED.iter().enumerate() {
        file[offset + i * 8..offset + (i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    let dir = std::env::temp_dir().join(format!("n0xis-exact-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".n0x")).expect("scratch dir");
    let image = dir.join("planted.so");
    std::fs::write(&image, file).expect("write the copy");
    Fixture { dir, image: image.to_string_lossy().into_owned(), addr }
}

fn n0x(dir: &Path, args: &[&str]) -> (Value, i32) {
    let out = support::isolated(Command::new(env!("CARGO_BIN_EXE_n0xis"))).args(args).current_dir(dir).output().expect("run n0xis");
    let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (v, out.status.code().unwrap_or(-1))
}

impl Fixture {
    fn window(&self) -> (String, String) {
        (format!("{:#x}", self.addr), (PLANTED.len() * 8).to_string())
    }

    /// `scan value` over the plant, by the command line.
    fn scan(&self, more: &[&str]) -> (Value, i32) {
        let (start, size) = self.window();
        let mut args = vec!["scan", "value", "--file", &self.image, "--start", &start, "--size", &size, "--save-as", "s", "--force"];
        args.extend_from_slice(more);
        n0x(&self.dir, &args)
    }

    /// `scan.value` over the plant, by the door a tool's arguments come through.
    fn capability(&self, name: &str, more: Value) -> Value {
        let (start, size) = self.window();
        let mut args = json!({ "file": self.image, "start": start, "size": size.parse::<u64>().unwrap(), "save_as": "s", "force": true });
        for (k, v) in more.as_object().expect("an object") {
            args[k] = v.clone();
        }
        n0x(&self.dir, &["capability", "run", name, "--args", &args.to_string()]).0
    }

    fn at(&self, slot: u64) -> String {
        format!("{:#x}", self.addr + slot * 8)
    }
}

fn addrs(v: &Value) -> Vec<String> {
    assert_eq!(v["ok"], true, "{v}");
    v["data"]["matches"].as_array().expect("matches").iter().map(|m| m["addr"].as_str().expect("addr").to_string()).collect()
}

#[test]
fn each_neighbour_a_double_cannot_tell_apart_is_found_alone() {
    let f = fixture("neighbours");
    for (slot, v) in PLANTED.iter().enumerate() {
        let (a, _) = f.scan(&["--type", "u64", "--align", "8", "--value", &v.to_string()]);
        assert_eq!(addrs(&a), vec![f.at(slot as u64)], "decimal {v}");
        let (a, _) = f.scan(&["--type", "u64", "--align", "8", "--value", &format!("{v:#x}")]);
        assert_eq!(addrs(&a), vec![f.at(slot as u64)], "hex {v:#x}");
    }
    assert_eq!(TWO_53 as f64, (TWO_53 + 1) as f64, "calibration: one double covers the first two");
}

#[test]
fn the_answer_prints_the_value_the_target_holds() {
    let f = fixture("printed");
    let (a, _) = f.scan(&["--type", "u64", "--align", "8", "--value", &(u64::MAX - 2).to_string()]);
    assert_eq!(a["data"]["matches"][0]["value"].as_u64(), Some(u64::MAX - 2), "{a}");
}

#[test]
fn a_signed_type_reads_the_same_bits_by_its_own_name() {
    let f = fixture("signed");
    let (a, _) = f.scan(&["--type", "i64", "--align", "8", "--value", "-3"]);
    assert_eq!(addrs(&a), vec![f.at(3)]);
    assert_eq!(a["data"]["matches"][0]["value"], -3);
}

#[test]
fn a_range_past_a_double_keeps_its_ends() {
    let f = fixture("range");
    let one = (TWO_53 + 1).to_string();
    let (a, _) = f.scan(&["--type", "u64", "--align", "8", "--criterion", "in-range", "--min", &one, "--max", &one]);
    assert_eq!(addrs(&a), vec![f.at(1)]);
}

#[test]
fn a_filter_binds_its_value_to_the_type_the_saved_scan_holds() {
    let f = fixture("filter");
    let (a, _) = f.scan(&["--type", "u64", "--align", "8", "--criterion", "unknown"]);
    assert_eq!(a["ok"], true, "{a}");
    let (a, _) = n0x(&f.dir, &["scan", "filter", "--file", &f.image, "--from", "s", "--save-as", "t", "--force", "--criterion", "exact", "--value", &(TWO_53 + 1).to_string()]);
    assert_eq!(addrs(&a), vec![f.at(1)]);
    // The saved type decides: this is fine as text and has no `u64`.
    let (a, _) = n0x(&f.dir, &["scan", "filter", "--file", &f.image, "--from", "s", "--save-as", "t", "--force", "--criterion", "exact", "--value", "-1"]);
    assert_eq!(a["error"]["code"], "bad-value", "{a}");
}

#[test]
fn what_a_type_cannot_hold_is_refused_and_not_answered_about() {
    let f = fixture("refused");
    for (ty, value) in [("i32", "4294967296"), ("u8", "300"), ("u32", "-1"), ("i64", "18446744073709551613"), ("u64", "18446744073709551616"), ("i32", "1.5"), ("f32", "16777217"), ("f64", "9007199254740993")] {
        let (a, rc) = f.scan(&["--type", ty, "--value", value]);
        assert_eq!(a["error"]["code"], "bad-value", "{ty} {value}: {a}");
        assert_ne!(rc, 0, "{ty} {value}");
    }
}

#[test]
fn a_flag_that_is_no_number_is_a_bad_flag() {
    let f = fixture("noflag");
    for value in ["nan", "inf", "abc"] {
        let (a, rc) = f.scan(&["--type", "f64", "--value", value]);
        assert_eq!(a["error"]["code"], "bad-arguments", "{value}: {a}");
        assert_eq!(rc, 2, "{value}");
    }
}

#[test]
fn a_tools_arguments_are_as_exact_as_the_request() {
    let f = fixture("json");
    let want = vec![f.at(1)];
    // A JSON integer, as serde holds it: exact.
    let a = f.capability("scan.value", json!({ "type": "u64", "align": 8, "value": TWO_53 + 1 }));
    assert_eq!(addrs(&a), want, "number");
    // Text, for a client whose own numbers are doubles.
    let a = f.capability("scan.value", json!({ "type": "u64", "align": 8, "value": (TWO_53 + 1).to_string() }));
    assert_eq!(addrs(&a), want, "string");
    // A double past 2^53 no longer says which integer it was, and is not answered about.
    let raw = format!(r#"{{"file":{:?},"start":{:?},"size":40,"save_as":"s","force":true,"type":"u64","value":9007199254740992.0}}"#, f.image, f.window().0);
    let (a, _) = n0x(&f.dir, &["capability", "run", "scan.value", "--args", &raw]);
    assert_eq!(a["error"]["code"], "bad-value", "{a}");
    // One past u64::MAX is a double by the time serde hands it over: the same.
    let raw = raw.replace("9007199254740992.0", "18446744073709551616");
    let (a, _) = n0x(&f.dir, &["capability", "run", "scan.value", "--args", &raw]);
    assert_eq!(a["error"]["code"], "bad-value", "{a}");
}

#[test]
fn a_group_field_is_as_exact_as_a_value() {
    let f = fixture("group");
    let field = |v: u64| json!({ "type": "x", "fields": [format!("u64={v}")], "align": 8 });
    let a = f.capability("scan.group", field(TWO_53 + 1));
    assert_eq!(a["data"]["total_hits"], 1, "{a}");
    let a = f.capability("scan.group", json!({ "fields": [format!("i32={}", 1u64 << 40)] }));
    assert_eq!(a["error"]["code"], "bad-value", "{a}");
}

/// A `pid` past `u32` was cut down to one that fits, so 2^32 + this process's id read
/// this process. A pid that is no pid names nothing.
#[test]
fn a_pid_too_large_names_no_process() {
    let f = fixture("pid");
    let own = 4_294_967_296u64 + u64::from(std::process::id());
    for capability in ["module.list", "mem.map", "strings"] {
        let (a, _) = n0x(&f.dir, &["capability", "run", capability, "--args", &json!({ "pid": own }).to_string()]);
        assert_eq!(a["ok"], false, "{capability}: {a}");
        assert_ne!(a["error"]["code"], "attach-failed", "{capability}: no process was tried: {a}");
    }
    // Calibration: the pid that fits is tried, whether or not the system lets it be read.
    let (a, _) = n0x(&f.dir, &["capability", "run", "module.list", "--args", &json!({ "pid": std::process::id() }).to_string()]);
    assert!(a["ok"] == true || a["error"]["code"] == "attach-failed", "{a}");
}
