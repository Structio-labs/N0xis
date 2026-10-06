// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A Windows program run by Wine is listed under its own name.
//!
//! Every such program's `/proc/<pid>/exe` is Wine's loader, so a listing that
//! names processes by that link calls them all `wine-preloader`, and
//! `--process app.exe` finds none of them. This builds a program whose name
//! is longer than the 15 bytes `comm` keeps, runs it under Wine, and looks
//! for it in the list by its full name. The kernel is the independent side:
//! its `exe` link says the process runs the loader, and its `comm` says the
//! process is this program, cut short.

#![cfg(all(feature = "oracle", feature = "live", target_os = "linux"))]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CC: &str = "x86_64-w64-mingw32-gcc";
const PROGRAM: &str = "n0xis-wine-name-probe.exe";
/// How much of a name the kernel keeps in `comm`.
const COMM_BYTES: usize = 15;

/// The program, stopped however the test ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_program_under_wine_is_listed_by_its_own_full_name() {
    let dir = std::env::temp_dir().join(format!("n0xis-wine-names-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch folder");
    std::fs::write(dir.join("probe.c"), "#include <windows.h>\nint main(void) { Sleep(60000); return 0; }\n").expect("the source");
    let built = Command::new(CC)
        .args(["-O1", "-o", PROGRAM, "probe.c"])
        .current_dir(&dir)
        .status()
        .unwrap_or_else(|e| panic!("this check builds its program with {CC}: {e}"));
    assert!(built.success(), "{CC} failed");
    let child = Command::new("wine")
        .arg(format!("./{PROGRAM}"))
        .current_dir(&dir)
        // The default prefix starts a .NET service that adds noise and seconds.
        .env("WINEDEBUG", "-all")
        .env("WINEDLLOVERRIDES", "mscoree=d")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("this check runs its program under wine: {e}"));
    let running = Running(child);
    let pid = running.0.id();

    // Wine starts as `wine` and turns into the program in the same process.
    let deadline = Instant::now() + Duration::from_secs(30);
    let listed = loop {
        let procs = n0xis_sources::list_processes().expect("walk /proc");
        let name = procs.iter().find(|p| p.pid == pid).map(|p| p.name.clone());
        if name.as_deref() == Some(PROGRAM) {
            break name;
        }
        assert!(Instant::now() < deadline, "pid {pid} was never listed as {PROGRAM}; last listed as {name:?}");
        std::thread::sleep(Duration::from_millis(200));
    };

    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).expect("the exe link");
    let loader = exe.file_name().expect("a file name").to_string_lossy().into_owned();
    assert!(loader.starts_with("wine"), "the premise: the kernel's exe link is Wine's loader, not the program ({exe:?})");
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).expect("comm");
    assert_eq!(comm.trim(), &PROGRAM[..COMM_BYTES], "the kernel's own name for this process, cut short");
    assert_eq!(listed.as_deref(), Some(PROGRAM));

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
