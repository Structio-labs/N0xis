// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Tiny audio feedback on cheat activation/deactivation — a clear two-tone
//! beep via the Win32 `Beep` (no extra crate/asset). `Beep` is synchronous
//! (blocks for its duration), so each call runs on a throwaway thread to keep
//! the caller — the hook thread, the watcher, or the UI — responsive.

use windows_sys::Win32::System::Diagnostics::Debug::Beep;

/// Higher tone — a cheat turned on.
pub fn activate() {
    std::thread::spawn(|| unsafe {
        Beep(880, 120);
    });
}

/// Lower tone — a cheat turned off.
pub fn deactivate() {
    std::thread::spawn(|| unsafe {
        Beep(440, 120);
    });
}
