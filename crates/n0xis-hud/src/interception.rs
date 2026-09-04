// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Key sender backed by the [Interception](https://github.com/oblitum/Interception)
//! kernel driver, dynamically loaded at runtime (no build-time link, no
//! hardcoded install path — the anti-hardcode rule: the DLL path is a
//! `hud.toml` setting, not baked into this crate).
//!
//! **Why not `SendInput`.** Confirmed live against a real target: some games
//! accept a real keypress but ignore the identical scancode sent via
//! `SendInput`, even with the game window focused — they filter
//! synthetic/injected input (the standard `LLKHF_INJECTED` check games use
//! against cheat input; see `input probe`, which detects this directly).
//! Interception delivers strokes through the keyboard class driver itself,
//! indistinguishable from hardware, so such a game accepts them.

use std::ffi::c_void;
use std::time::Duration;

use libloading::{Library, Symbol};

type CreateContextFn = unsafe extern "C" fn() -> *mut c_void;
type DestroyContextFn = unsafe extern "C" fn(*mut c_void);
type IsKeyboardFn = unsafe extern "C" fn(i32) -> i32;
type SendFn = unsafe extern "C" fn(*mut c_void, i32, *const u8, u32) -> i32;

/// One 20-byte `InterceptionStroke` holding a keyboard stroke:
/// `{ u16 code; u16 state; u32 information; }` then zero padding (the struct
/// is sized to the larger `InterceptionMouseStroke` union member).
const STROKE_LEN: usize = 20;
const KEY_DOWN: u16 = 0x00;
const KEY_UP: u16 = 0x01;

fn scancode(direction: &str) -> Option<u16> {
    // WASD, matching the stratagem-direction bind confirmed live (up=W,
    // down=S, left=A, right=D) — not hardcoded elsewhere, this is the one
    // place the mapping lives.
    Some(match direction.to_ascii_lowercase().as_str() {
        "up" => 0x11,
        "down" => 0x1F,
        "left" => 0x1E,
        "right" => 0x20,
        _ => return None,
    })
}

fn key_stroke(code: u16, state: u16) -> [u8; STROKE_LEN] {
    let mut b = [0u8; STROKE_LEN];
    b[0..2].copy_from_slice(&code.to_le_bytes());
    b[2..4].copy_from_slice(&state.to_le_bytes());
    b
}

/// A loaded Interception context, ready to send keyboard strokes. Not
/// `Send`/`Sync` (raw driver handle) — create one per thread that needs it,
/// same rule as [`n0xis_sources::LiveProcess`].
pub struct KeySender {
    _lib: Library, // keeps the DLL mapped for the sender's lifetime
    ctx: *mut c_void,
    device: i32,
    destroy_context: DestroyContextFn,
    send: SendFn,
    pub hold_ms: u64,
    pub gap_ms: u64,
}

impl KeySender {
    /// Load `interception.dll` from `dll_path` and open a context. `None`
    /// device auto-picks the first keyboard device (1..=10).
    pub fn open(dll_path: &str, device: Option<i32>, hold_ms: u64, gap_ms: u64) -> Result<Self, String> {
        // SAFETY: loading a user-configured DLL and resolving its documented
        // C ABI exports; the driver's own API contract governs correctness.
        let lib = unsafe { Library::new(dll_path) }.map_err(|e| format!("load '{dll_path}': {e}"))?;
        unsafe {
            let create_context: Symbol<CreateContextFn> =
                lib.get(b"interception_create_context\0").map_err(|e| e.to_string())?;
            let destroy_context: Symbol<DestroyContextFn> =
                lib.get(b"interception_destroy_context\0").map_err(|e| e.to_string())?;
            let is_keyboard: Symbol<IsKeyboardFn> = lib.get(b"interception_is_keyboard\0").map_err(|e| e.to_string())?;
            let send: Symbol<SendFn> = lib.get(b"interception_send\0").map_err(|e| e.to_string())?;

            let create_context = *create_context;
            let destroy_context = *destroy_context;
            let is_keyboard = *is_keyboard;
            let send = *send;

            let ctx = create_context();
            if ctx.is_null() {
                return Err("interception_create_context returned null — is the driver installed and rebooted?".into());
            }
            let dev = match device {
                Some(d) if is_keyboard(d) != 0 => d,
                _ => (1..=10).find(|&d| is_keyboard(d) != 0).unwrap_or(1),
            };
            Ok(KeySender { _lib: lib, ctx, device: dev, destroy_context, send, hold_ms, gap_ms })
        }
    }

    /// Press or release one raw scancode (for a held modifier like Ctrl).
    fn key(&self, code: u16, down: bool) {
        let s = key_stroke(code, if down { KEY_DOWN } else { KEY_UP });
        unsafe { (self.send)(self.ctx, self.device, s.as_ptr(), 1) };
    }

    /// Run a stratagem macro: hold `modifier` (a raw scancode, e.g. Left-Ctrl
    /// `0x1D`) down for the whole input, tap each direction (each held for
    /// `self.hold_ms`, `self.gap_ms` between taps — the same speed knobs the
    /// HUD's "Stratagems" panel exposes), then release the modifier last. This
    /// is the generic "hold a modifier, tap the directions" shape a
    /// stratagem/macro code is read with. Returns `false` on an unmapped
    /// direction.
    pub fn run_stratagem(&self, modifier: u16, directions: &[String]) -> bool {
        let codes: Vec<u16> = match directions.iter().map(|d| scancode(d)).collect::<Option<_>>() {
            Some(c) => c,
            None => return false,
        };
        self.key(modifier, true);
        std::thread::sleep(Duration::from_millis(self.hold_ms));
        for code in codes {
            self.key(code, true);
            std::thread::sleep(Duration::from_millis(self.hold_ms));
            self.key(code, false);
            std::thread::sleep(Duration::from_millis(self.gap_ms));
        }
        self.key(modifier, false);
        true
    }
}

/// Left-Ctrl scancode — a common stratagem/macro-input modifier key.
pub const LEFT_CTRL: u16 = 0x1D;

impl Drop for KeySender {
    fn drop(&mut self) {
        unsafe { (self.destroy_context)(self.ctx) };
    }
}

// `create_context`/`destroy_context`/`send` above are plain fn pointers
// (Copy), so the struct itself only needs `unsafe impl Send` for the raw
// `ctx` pointer — but per Interception's own docs a context must not be used
// concurrently from multiple threads, so this is deliberately **not**
// Send/Sync; each solver thread opens its own `KeySender`.
