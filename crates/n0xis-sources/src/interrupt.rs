// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A debugger command interrupted by the person who started it.
//!
//! While one of these commands waits, the target carries something of ours: a `0xCC`
//! in its code or a live debug register. A process that dies on Ctrl-C leaves that
//! behind, and on Windows the target then died with 0x80000003 at its next pass over
//! the byte. So for as long as a command waits, Ctrl-C, Ctrl-Break, closing the console,
//! `SIGINT`, `SIGTERM` and `SIGHUP` only ask it to stop: the wait loop sees the request
//! within one poll, and the guards that own the byte and the attach do what they do on
//! any other way out.
//!
//! `SIGKILL` and `TerminateProcess` cannot be handled. What those leave is recorded
//! before it is written: see `n0xis_project::patch::record_planted`.

use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

/// Whether the person asked this command to stop.
pub(crate) fn requested() -> bool {
    STOP.load(Ordering::Relaxed)
}

/// The handlers, for as long as this lives. The first thing a wait holds and so the last
/// thing it lets go of, after the byte is back and the debugger gone.
pub(crate) struct Interruptible {
    #[cfg(unix)]
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

#[cfg(unix)]
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

#[cfg(unix)]
impl Interruptible {
    pub(crate) fn install() -> Self {
        STOP.store(false, Ordering::Relaxed);
        let mut previous = Vec::new();
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // No `SA_RESTART`: a sleep or a wait a signal interrupts returns, and the loop looks.
            let mut ours: libc::sigaction = unsafe { std::mem::zeroed() };
            ours.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(signal, &ours, &mut old) } == 0 {
                // A signal this process was started ignoring (`nohup`) stays ignored:
                // whoever started it asked for that.
                if old.sa_sigaction == libc::SIG_IGN {
                    unsafe { libc::sigaction(signal, &old, std::ptr::null_mut()) };
                } else {
                    previous.push((signal, old));
                }
            }
        }
        Interruptible { previous }
    }
}

#[cfg(unix)]
impl Drop for Interruptible {
    fn drop(&mut self) {
        for (signal, old) in &self.previous {
            unsafe { libc::sigaction(*signal, old, std::ptr::null_mut()) };
        }
    }
}

#[cfg(windows)]
mod console {
    use super::*;
    use windows_sys::core::BOOL;
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};

    /// The wait has let go of the target. A console closing or a session ending ends this
    /// process when the handler returns, so the handler holds it until then.
    static LEFT: AtomicBool = AtomicBool::new(false);
    /// Windows allows a handler about 5 seconds for these before it ends the process anyway.
    const HOLD: std::time::Duration = std::time::Duration::from_secs(4);

    pub(super) unsafe extern "system" fn on_event(kind: u32) -> BOOL {
        STOP.store(true, Ordering::Relaxed);
        if kind != CTRL_C_EVENT && kind != CTRL_BREAK_EVENT {
            let started = std::time::Instant::now();
            while !LEFT.load(Ordering::Relaxed) && started.elapsed() < HOLD {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        1
    }

    pub(super) fn set_left(left: bool) {
        LEFT.store(left, Ordering::Relaxed);
    }
}

#[cfg(windows)]
impl Interruptible {
    pub(crate) fn install() -> Self {
        STOP.store(false, Ordering::Relaxed);
        console::set_left(false);
        unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(console::on_event), 1) };
        Interruptible {}
    }
}

#[cfg(windows)]
impl Drop for Interruptible {
    fn drop(&mut self) {
        console::set_left(true);
        unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(console::on_event), 0) };
    }
}
