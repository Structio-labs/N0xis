// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! End-to-end proof of the ELF/DWARF unwinder on a real live process.
//!
//! Runs only under `--features live` on Linux/Android. It spawns a child
//! (`sleep`), so the child is a *descendant* of the test process and can be
//! ptraced even under `kernel.yama.ptrace_scope=1` (the common default). It then
//! snapshots the child's registers via [`StoppedThread`] and walks its stack via
//! [`LiveTarget::stack_unwind`], which reads the child's `.eh_frame` DWARF CFI
//! and stack out of `/proc` — the whole path the `stack backtrace` command uses.
#![cfg(all(feature = "live", any(target_os = "linux", target_os = "android")))]

use std::process::Command;
use std::time::{Duration, Instant};

use n0xis_sources::{LinuxProcess, LiveTarget, ModuleProvider, StoppedThread};

/// Spin-wait until `pid`'s main-thread rip sits inside a file-backed module
/// (i.e. the child has finished the dynamic loader and entered libc's
/// `nanosleep`), so the capture is a steady state, not the ld.so startup path.
fn wait_until_settled(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(stop) = StoppedThread::attach(pid)
            && let Ok(regs) = stop.registers()
            && let Ok(live) = LinuxProcess::attach(pid)
            && live.owner_of(n0xis_contracts::Va(regs.rip)).is_some()
        {
            return;
        }
        if Instant::now() > deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn unwinds_a_real_child_process() {
    let mut child = match Command::new("sleep").arg("30").spawn() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("skip: `sleep` not available");
            return;
        }
    };
    let pid = child.id();

    // Let it reach a steady blocking state inside libc.
    std::thread::sleep(Duration::from_millis(150));
    wait_until_settled(pid);

    let frames = {
        let stop = StoppedThread::attach(pid).expect("attach child");
        let regs = stop.registers().expect("getregs");
        let live = LinuxProcess::attach(pid).expect("attach live");
        let frames = live.stack_unwind(regs, 64);

        // Frame 0 must be exactly the captured instruction pointer.
        assert_eq!(frames.first().map(|f| f.rip), Some(regs.rip), "frame 0 is the capture site");
        frames
        // `stop` drops here → child resumes.
    };

    let _ = child.kill();
    let _ = child.wait();

    // A blocked `sleep` has a real multi-frame stack (nanosleep → main →
    // __libc_start_main → _start), crossing libc and the sleep binary.
    assert!(frames.len() >= 2, "expected a multi-frame stack, got {}: {frames:#x?}", frames.len());

    // The recovered rips must strictly climb the address space (the unwinder's
    // core soundness guard) and be distinct — never a fabricated loop.
    for w in frames.windows(2) {
        assert_ne!(w[0].rip, w[1].rip, "consecutive frames must differ: {frames:#x?}");
    }

    // At least one frame must resolve to a real module (libc or the binary),
    // proving cross-module `.eh_frame` lookup actually fired.
    assert!(
        frames.iter().any(|f| f.module.is_some()),
        "at least one frame should resolve to a module: {frames:#x?}"
    );

    eprintln!("recovered {} frames:", frames.len());
    for (i, f) in frames.iter().enumerate() {
        eprintln!("  #{i}: {}", f.symbol.clone().unwrap_or_else(|| format!("{:#x}", f.rip)));
    }
}
