// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Variant A: replay a fixed direction combo by synthesizing key presses
//! (`SendInput`), with a configurable per-step delay. The game's combo
//! mini-game reads directional input each frame; we tap the mapped keys in
//! order, and the game's own (unmodified) `check_input_combo` accepts them —
//! no memory patch, no bypass.
//!
//! **Honest limit (same class as the overlay input note):** `SendInput`
//! injects at the OS message/RAWINPUT layer. Most games see it; a title
//! reading the keyboard through DirectInput device state might not. If a combo
//! doesn't register in-game, that's the cause — the fallback is the runtime
//! `input_queue` write (variant C, documented in cheats_research.md), not a
//! bigger delay.

use std::thread;
use std::time::Duration;

use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP,
};

use crate::input::is_extended_key;

fn key_event(vk: u16, up: bool) -> INPUT {
    let mut flags = if up { KEYEVENTF_KEYUP } else { 0 };
    if is_extended_key(vk) {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT { wVk: vk, wScan: 0, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    }
}

fn tap(vk: u16, press_ms: u64) {
    let down = key_event(vk, false);
    unsafe { SendInput(1, &down, std::mem::size_of::<INPUT>() as i32) };
    thread::sleep(Duration::from_millis(press_ms.max(1)));
    let up = key_event(vk, true);
    unsafe { SendInput(1, &up, std::mem::size_of::<INPUT>() as i32) };
}

/// Replay `vks` in order on a background thread: tap each key (held for
/// `press_ms`), then wait `delay_ms` before the next. Runs off-thread so the
/// caller (UI or hook) never blocks for the whole sequence.
pub fn run(vks: Vec<u16>, delay_ms: u64, press_ms: u64) {
    thread::spawn(move || {
        for (i, vk) in vks.iter().enumerate() {
            if i > 0 {
                thread::sleep(Duration::from_millis(delay_ms));
            }
            tap(*vk, press_ms);
        }
    });
}
