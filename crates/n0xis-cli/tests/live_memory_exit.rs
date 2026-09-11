// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Live-memory exit test** — the 27% of the command surface that had no
//! oracle at all.
//!
//! Thirty-one commands read, write, patch, scan, watch and freeze another
//! process's memory, and until this test every one of them was believed rather
//! than measured: there is no static fixture for a running program, so nothing
//! checked them. This spawns a disposable target that *plants* known values at
//! addresses it prints, then answers each command against a source outside
//! n0xis entirely — `/proc/<pid>/mem` and `/proc/<pid>/maps`, the kernel's own
//! view:
//!
//! * a read is right when it equals the kernel's bytes;
//! * a write is right when the kernel shows it afterwards;
//! * `patch undo` is right when the bytes are back, byte for byte;
//! * a dry run is right when nothing in the process changed;
//! * a scan is right when the planted address is among the hits;
//! * a watchpoint is right when it fires on the target's *own* store.
//!
//! That last one is why the target writes `WATCHED` itself: a hardware
//! watchpoint lives in the CPU's debug registers and sees only the thread's
//! accesses, so a harness that pokes through `/proc/<pid>/mem` trips nothing.
//! The first version of this measurement did exactly that and recorded the
//! silence as a defect.
//!
//! Linux-only, because the objective source is. `patch detour` and
//! `table freeze` are Windows-only in the product and are asserted to *say so*
//! rather than being silently skipped — an unimplemented path that answers
//! "unsupported on this build" is a kept promise; one that answers nothing is
//! not.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::Value;

/// The disposable target. Every value exists so a check can be objective.
const TARGET_SRC: &str = r##"
#![allow(static_mut_refs)]
use std::time::Duration;

static mut MARKER: [u8; 32] = [0xAB; 32];
static mut HEALTH: i32 = 1000;
static mut PATTERN: [u8; 16] = [0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44,
                                0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC];
static mut COUNTER: u64 = 0x1122334455667788;
/// Written by the target's own thread every tick, so a debug register sees it.
static mut WATCHED: u64 = 0;

#[repr(C)]
struct Entity { hp: i32, mp: i32, x: f32, y: f32, flags: u64, name: *const u8 }
static NAME: &[u8] = b"oracle\0";
static mut ENTITY: Entity =
    Entity { hp: 4242, mp: 99, x: 1.5, y: -2.5, flags: 0x0102030405060708, name: std::ptr::null() };
static mut ENTITY_PTR: *const Entity = std::ptr::null();

unsafe extern "C" { fn prctl(o: i32, a: u64, b: u64, c: u64, d: u64) -> i32; }

#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn n0x_tick(n: u64) -> u64 {
    unsafe {
        std::ptr::write_volatile(&raw mut WATCHED, n);
        std::ptr::read_volatile(&raw const COUNTER).wrapping_add(n)
    }
}

fn main() {
    // Yama's default lets only an ancestor read this process, and the harness
    // runs n0xis as a sibling. The target grants the permission itself — the
    // opt-in a debuggee normally makes — so the test needs no privileges.
    unsafe { prctl(0x59616d61, u64::MAX, 0, 0, 0) };
    unsafe {
        ENTITY.name = NAME.as_ptr();
        ENTITY_PTR = &raw const ENTITY;
        println!("pid={}", std::process::id());
        println!("marker=0x{:x}", &raw const MARKER as usize);
        println!("health=0x{:x}", &raw const HEALTH as usize);
        println!("pattern=0x{:x}", &raw const PATTERN as usize);
        println!("entity=0x{:x}", &raw const ENTITY as usize);
        println!("watched=0x{:x}", &raw const WATCHED as usize);
        println!("tick=0x{:x}", n0x_tick as usize);
        println!("ready");
    }
    let mut n = 0u64;
    loop {
        n = n0x_tick(n) & 0xffff;
        std::thread::sleep(Duration::from_millis(20));
    }
}
"##;

struct Target {
    child: Child,
    pid: u32,
    sym: HashMap<String, u64>,
    dir: std::path::PathBuf,
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Target {
    fn at(&self, name: &str) -> u64 {
        *self.sym.get(name).unwrap_or_else(|| panic!("target printed no {name}="))
    }

    /// The kernel's view of the target's memory — the source outside n0xis.
    fn peek(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut f = std::fs::File::open(format!("/proc/{}/mem", self.pid)).expect("open /proc/pid/mem");
        f.seek(SeekFrom::Start(addr)).expect("seek");
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).expect("read target memory");
        buf
    }

    fn poke(&self, addr: u64, bytes: &[u8]) {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/{}/mem", self.pid))
            .expect("open /proc/pid/mem for write");
        f.seek(SeekFrom::Start(addr)).expect("seek");
        f.write_all(bytes).expect("write target memory");
    }

    fn n0x(&self, args: &[&str]) -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_n0xis"))
            .args(args)
            .current_dir(&self.dir)
            .output()
            .expect("run n0xis");
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!("n0xis {args:?} did not print one JSON object: {e}\n{}", String::from_utf8_lossy(&out.stdout))
        })
    }

    fn ok(&self, args: &[&str]) -> Value {
        let v = self.n0x(args);
        assert!(v["ok"].as_bool().unwrap_or(false), "n0xis {args:?} failed: {}", v["error"]);
        v["data"].clone()
    }
}

fn spawn_target() -> Target {
    // Every test in this file spawns its own target and its own `.n0x`, and
    // they run in one process — a directory keyed only on the pid would put
    // them all in the same project and let one test's patches and tables show
    // up in another's assertions.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("n0xis-live-oracle-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let src = dir.join("target.rs");
    let exe = dir.join("target");
    std::fs::write(&src, TARGET_SRC).expect("write target source");
    let out = Command::new("rustc")
        .args(["-O", "-o"])
        .arg(&exe)
        .arg(&src)
        .output()
        .expect("invoke rustc (it built this crate, so it is on PATH)");
    assert!(
        out.status.success(),
        "rustc failed to build the disposable target:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut child =
        Command::new(&exe).stdout(Stdio::piped()).current_dir(&dir).spawn().expect("spawn target");
    let mut out = child.stdout.take().expect("piped stdout");
    // Read until the target says it has published every address.
    let mut text = String::new();
    let mut buf = [0u8; 256];
    for _ in 0..200 {
        if let Ok(n) = out.read(&mut buf) {
            text.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        if text.contains("ready") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(text.contains("ready"), "target never became ready: {text:?}");

    let mut sym = HashMap::new();
    let mut pid = 0u32;
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        if k == "pid" {
            pid = v.trim().parse().expect("pid");
        } else if let Some(h) = v.trim().strip_prefix("0x") {
            sym.insert(k.to_string(), u64::from_str_radix(h, 16).expect("hex address"));
        }
    }
    assert!(pid != 0, "no pid line");

    let t = Target { child, pid, sym, dir };
    t.ok(&["init", "--name", "liveoracle"]);
    t
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn addrs(data: &Value, key: &str) -> Vec<u64> {
    // A result list holds either bare hex strings or objects with an address
    // field. Walking the whole `data` instead would pick the query back up and
    // "find" an address in an empty result.
    let mut out = Vec::new();
    for it in data[key].as_array().into_iter().flatten() {
        let s = it.as_str().or_else(|| {
            ["addr", "address", "va", "base", "start"].iter().find_map(|k| it[*k].as_str())
        });
        if let Some(s) = s.and_then(|s| s.strip_prefix("0x"))
            && let Ok(v) = u64::from_str_radix(s, 16)
        {
            out.push(v);
        }
    }
    out
}

// ------------------------------------------------------------------ mem -----

#[test]
fn mem_read_write_and_map_agree_with_the_kernel() {
    let t = spawn_target();
    let a = t.at("marker");

    let d = t.ok(&["mem", "read", "--pid", &t.pid.to_string(), "--addr", &format!("{a:#x}"), "--size", "32"]);
    let got = d["hex"].as_str().expect("hex").replace(' ', "");
    assert_eq!(got, hex_of(&t.peek(a, 32)).replace(' ', ""), "mem read must equal /proc/pid/mem");
    assert_eq!(d["read"], 32, "a read reports how much it actually got");

    let original = t.peek(a, 8);
    t.ok(&[
        "mem", "write", "--pid", &t.pid.to_string(), "--addr", &format!("{a:#x}"),
        "--bytes", "01 02 03 04 05 06 07 08",
    ]);
    assert_eq!(t.peek(a, 8), vec![1, 2, 3, 4, 5, 6, 7, 8], "the kernel must show the written bytes");
    t.poke(a, &original);

    let d = t.ok(&["mem", "map", "--pid", &t.pid.to_string(), "--limit", "200"]);
    let kernel: Vec<(u64, u64)> = std::fs::read_to_string(format!("/proc/{}/maps", t.pid))
        .expect("maps")
        .lines()
        .filter_map(|l| {
            let (s, e) = l.split_whitespace().next()?.split_once('-')?;
            Some((u64::from_str_radix(s, 16).ok()?, u64::from_str_radix(e, 16).ok()?))
        })
        .collect();
    let regions = d["regions"].as_array().expect("regions");
    assert!(!regions.is_empty());
    for r in regions {
        let base = r["base"].as_str().or_else(|| r["start"].as_str()).expect("a region base");
        let b = u64::from_str_radix(base.trim_start_matches("0x"), 16).expect("hex");
        assert!(
            kernel.iter().any(|(s, e)| *s <= b && b < *e),
            "mem map reports {base}, which /proc/pid/maps does not map"
        );
    }
}

// ---------------------------------------------------------------- patch -----

#[test]
fn a_patch_is_applied_journaled_and_undone_byte_for_byte() {
    let t = spawn_target();
    let a = t.at("marker");
    let pid = t.pid.to_string();
    let at = format!("{a:#x}");
    let original = t.peek(a, 4);

    // A dry run's entire promise is that the process is untouched.
    t.ok(&["patch", "dry-run", "--pid", &pid, "--addr", &at, "--bytes", "aa bb cc dd"]);
    assert_eq!(t.peek(a, 4), original, "a dry run must not modify the process");

    let d = t.ok(&["patch", "apply", "--pid", &pid, "--addr", &at, "--bytes", "aa bb cc dd"]);
    assert_eq!(t.peek(a, 4), vec![0xAA, 0xBB, 0xCC, 0xDD], "the kernel must show the patch");
    let id = d["id"].as_str().expect("a patch id").to_string();

    let d = t.ok(&["patch", "list"]);
    assert!(
        d["items"].as_array().expect("items").iter().any(|p| p["id"].as_str() == Some(&id)),
        "the applied patch must be journaled"
    );

    let d = t.ok(&["patch", "show", "--id", &id]);
    assert_eq!(
        d["item"]["before_hex"].as_str().unwrap_or_default().replace(' ', ""),
        hex_of(&original).replace(' ', ""),
        "the journal must record the bytes that were actually there"
    );

    // `all` is the spelling a caller reaches for, and it once returned nothing.
    let all = t.ok(&["patch", "list", "--status", "all"]);
    let bare = t.ok(&["patch", "list"]);
    assert_eq!(all["count"], bare["count"], "--status all must mean every patch");
    assert_eq!(t.ok(&["patch", "list", "--status", "applied"])["count"], serde_json::json!(1));

    t.ok(&["patch", "undo", "--id", &id, "--pid", &pid]);
    assert_eq!(t.peek(a, 4), original, "undo must restore the original bytes exactly");
    assert_eq!(t.ok(&["patch", "list", "--status", "undone"])["count"], serde_json::json!(1));
}

/// An unimplemented path must refuse in the contract, not answer nothing.
#[test]
fn the_windows_only_live_paths_say_they_are_windows_only() {
    let t = spawn_target();
    let pid = t.pid.to_string();
    // The gate must be reached, so the entry has to exist first — otherwise the
    // command refuses for the ordinary reason and proves nothing.
    t.ok(&["table", "add", "--table", "t", "--name", "hp", "--addr", &format!("{:#x}", t.at("health")), "--type", "i32"]);
    for args in [
        vec!["patch", "detour", "--pid", &pid, "--hook-at", "0x1000", "--cave-size", "32"],
        vec!["table", "freeze", "--table", "t", "--name", "hp", "--pid", &pid, "--value", "1"],
    ] {
        let v = t.n0x(&args);
        assert_eq!(v["ok"], serde_json::json!(false), "{args:?} should refuse on Linux");
        assert_eq!(
            v["error"]["code"], "live-unsupported",
            "{args:?} must name the platform gate, not fail generically: {}",
            v["error"]
        );
    }
}

// ----------------------------------------------------------------- scan -----

#[test]
fn a_scan_finds_the_values_the_target_planted() {
    let t = spawn_target();
    let pid = t.pid.to_string();
    let health = t.at("health");

    let d = t.ok(&[
        "scan", "value", "--pid", &pid, "--type", "i32", "--criterion", "exact",
        "--value", "1000", "--save-as", "s1", "--force",
    ]);
    assert!(addrs(&d, "matches").contains(&health), "the planted i32=1000 must be among the hits");

    // Narrowing is only meaningful against a change the harness made itself.
    t.poke(health, &777i32.to_le_bytes());
    let d = t.ok(&[
        "scan", "filter", "--pid", &pid, "--from", "s1", "--criterion", "exact",
        "--value", "777", "--save-as", "s2", "--force",
    ]);
    assert!(addrs(&d, "matches").contains(&health), "the address whose value changed must survive");
    t.poke(health, &1000i32.to_le_bytes());

    let d = t.ok(&["scan", "aob", "--pid", &pid, "--pattern", "DE AD BE EF ?? ?? 33 44"]);
    assert!(addrs(&d, "matches").contains(&t.at("pattern")), "the planted byte pattern must be found");

    let entity = t.at("entity");
    let d = t.ok(&[
        "scan", "pointer-path", "--pid", &pid, "--target", &format!("{entity:#x}"),
        "--module", "target", "--max-depth", "3",
    ]);
    assert!(!d["paths"].as_array().expect("paths").is_empty(), "a static pointer points at the planted object");

    let d = t.ok(&["scan", "dissect", "--pid", &pid, "--start", &format!("{entity:#x}"), "--size", "32"]);
    assert_eq!(d["requested"], 32);
    assert_eq!(d["read"], 32, "a partial dissection must be visible, not silent");
    assert_eq!(d["truncated"], serde_json::json!(false));
    let fields = d["fields"].as_array().expect("fields");
    let at0 = fields.iter().find(|f| f["offset"] == 0).expect("a field at +0");
    assert_eq!(
        at0["raw_hex"].as_str().unwrap_or_default().replace(' ', ""),
        hex_of(&4242i32.to_le_bytes()).replace(' ', ""),
        "the planted i32 at +0 must be read back exactly"
    );
    // The pointer slot is dissected on its own rather than looked for at +24 of
    // the struct. `classify` is greedy and tries the widest interpretation
    // first, so the 8-byte window at +20 — four bytes of `flags` plus the low
    // four of the pointer — is itself read as a double whenever the pointer's
    // fourth byte lands in the exponent range, which ASLR makes true 3.1% of
    // the time (0x3e/0x3f/0x40/0x41 and their negatives). That is the
    // documented heuristic working as specified, with the confidence it
    // advertises; an assertion that depends on which side of a 1-in-32 coin
    // ASLR landed measures the coin.
    let d = t.ok(&[
        "scan", "dissect", "--pid", &pid, "--start", &format!("{:#x}", entity + 24), "--size", "8",
    ]);
    let f0 = &d["fields"][0];
    assert_eq!(f0["offset"], 0);
    assert_eq!(f0["kind"], "pointer", "the planted pointer must be recognised as one: {d}");
    assert_eq!(f0["size"], 8);
}

// ---------------------------------------------------------------- debug -----

#[test]
fn a_watchpoint_fires_on_the_targets_own_store_and_a_breakpoint_on_its_own_call() {
    let t = spawn_target();
    let pid = t.pid.to_string();

    let d = t.ok(&["debug", "attach", "--pid", &pid, "--timeout-ms", "2000"]);
    let _ = d;
    assert!(
        std::path::Path::new(&format!("/proc/{}/status", t.pid)).exists(),
        "attaching must not kill the target"
    );

    // `watched` is stored by the target's own thread every tick; a debug
    // register only sees the thread's accesses.
    let w = format!("{:#x}", t.at("watched"));
    let d = t.ok(&[
        "debug", "watch", "--pid", &pid, "--addr", &w, "--kind", "write", "--len", "8",
        "--timeout-ms", "6000",
    ]);
    assert_eq!(d["timed_out"], serde_json::json!(false), "the watchpoint must fire: {d}");
    assert!(d["hit"]["rip"].is_string(), "a hit must name the instruction that made the store: {d}");

    let tick = format!("{:#x}", t.at("tick"));
    let d = t.ok(&["debug", "await-hit", "--pid", &pid, "--addr", &tick, "--timeout-ms", "6000"]);
    assert_eq!(d["timed_out"], serde_json::json!(false), "a breakpoint on a hot function must be hit: {d}");
}

// -------------------------------------------------- project-scoped state ----

#[test]
fn selections_dumps_and_tables_round_trip_through_the_project() {
    let t = spawn_target();
    let a = t.at("marker");
    let (start, end) = (format!("{a:#x}"), format!("{:#x}", a + 32));

    t.ok(&["selection", "save", "--name", "s", "--start", &start, "--end", &end, "--label", "marker"]);
    let d = t.ok(&["selection", "list"]);
    assert!(d.to_string().contains("\"s\""), "a saved selection must be listed: {d}");
    assert!(t.ok(&["selection", "show", "--name", "s"]).to_string().contains(&format!("{a:x}")));
    t.ok(&["selection", "clear", "--name", "s"]);
    assert!(!t.ok(&["selection", "list"]).to_string().contains("\"name\":\"s\""));

    // A raw dump must preview exactly the process bytes it was given.
    let blob = t.dir.join("marker.bin");
    std::fs::write(&blob, t.peek(a, 32)).expect("write blob");
    t.ok(&["dump", "save", "--name", "d1", "--kind", "raw", "--file", blob.to_str().unwrap(), "--force"]);
    assert!(t.ok(&["dump", "list"]).to_string().contains("d1"));
    let d = t.ok(&["dump", "show", "--name", "d1", "--kind", "raw", "--preview", "64"]);
    assert_eq!(
        d["content"].as_str().unwrap_or_default().replace(' ', ""),
        hex_of(&t.peek(a, 32)).replace(' ', ""),
        "the dump must preview the bytes it came from"
    );
    t.ok(&["dump", "rm", "--name", "d1", "--kind", "raw"]);
    assert!(!t.ok(&["dump", "list"]).to_string().contains("d1"));

    let h = format!("{:#x}", t.at("health"));
    t.ok(&["table", "add", "--table", "t", "--name", "hp", "--addr", &h, "--type", "i32"]);
    assert!(t.ok(&["table", "list", "--table", "t"]).to_string().contains("hp"));
    assert!(t
        .ok(&["table", "show", "--table", "t", "--name", "hp"])
        .to_string()
        .contains(&format!("{:x}", t.at("health"))));
    t.ok(&["table", "rm", "--table", "t", "--name", "hp"]);
    assert!(!t.ok(&["table", "list", "--table", "t"]).to_string().contains("\"hp\""));
}
