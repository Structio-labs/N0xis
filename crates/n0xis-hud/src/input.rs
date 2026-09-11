// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Global low-level keyboard hook. It runs on its own thread and acts on key
//! presses *directly* — toggling a cheat via the shared [`Engine`], or
//! showing/hiding the N0xHUD window — so hotkeys work while the game is
//! focused *and* while the N0xHUD window is hidden (neither depends on the
//! egui UI ticking).
//!
//! A key acts only on its down-transition (not auto-repeat), so holding it
//! toggles once.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, FindWindowW, GetMessageW, IsWindowVisible, SetForegroundWindow,
    SetWindowsHookExW, ShowWindow, TranslateMessage, KBDLLHOOKSTRUCT, LLKHF_INJECTED, MSG, SW_HIDE, SW_SHOW,
    WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
};

use crate::engine::Engine;

static ENGINE: OnceLock<Arc<Mutex<Engine>>> = OnceLock::new();
/// VK of the window show/hide key (0 = unset).
static TOGGLE_VK: AtomicU32 = AtomicU32::new(0);
/// Keys currently held, so auto-repeat doesn't re-fire a toggle.
static HELD: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// Map a config string (`"F5"`, `"A"`, `"1"`, ...) to a VK code. Unrecognized
/// names return 0 (matches no real key).
/// The window show/hide key currently in effect, so the engine can refuse a
/// cheat rebind that would collide with it (the window-toggle branch runs
/// first in `handle_key_down` and would swallow such a key before any cheat
/// ever saw it).
pub fn window_toggle_vk() -> u32 {
    TOGGLE_VK.load(Ordering::Relaxed)
}

pub fn parse_vk(name: &str) -> u32 {
    let up = name.trim().to_ascii_uppercase();
    // Named keys (arrows, common editing/whitespace keys) — needed for combo
    // direction binds and window keys beyond the alphanumeric/F-key range.
    match up.as_str() {
        "UP" => return 0x26,
        "DOWN" => return 0x28,
        "LEFT" => return 0x25,
        "RIGHT" => return 0x27,
        "SPACE" => return 0x20,
        "ENTER" | "RETURN" => return 0x0D,
        "TAB" => return 0x09,
        "SHIFT" => return 0x10,
        "CTRL" | "CONTROL" => return 0x11,
        "ALT" => return 0x12,
        "ESC" | "ESCAPE" => return 0x1B,
        "BACKSPACE" => return 0x08,
        _ => {}
    }
    if let Some(n) = up.strip_prefix('F')
        && let Ok(n) = n.parse::<u32>()
        && (1..=24).contains(&n)
    {
        return 0x70 + (n - 1); // VK_F1 == 0x70
    }
    if up.len() == 1 {
        let c = up.as_bytes()[0];
        if c.is_ascii_alphanumeric() {
            return c as u32; // VK codes for '0'-'9'/'A'-'Z' match ASCII
        }
    }
    0
}

/// Is `vk` one of the extended keys that `SendInput` must flag with
/// `KEYEVENTF_EXTENDEDKEY` (arrow keys, nav cluster) to register correctly?
pub fn is_extended_key(vk: u16) -> bool {
    matches!(vk, 0x25..=0x28) // LEFT/UP/RIGHT/DOWN
}

fn handle_key_down(vk: u32) {
    let toggle = TOGGLE_VK.load(Ordering::Relaxed);
    if vk != 0 && vk == toggle {
        toggle_hud_window();
    } else if let Some(engine) = ENGINE.get()
        && let Ok(mut e) = engine.lock()
    {
        e.handle_hotkey(vk);
    }
}

/// Is `vk` bound to a HUD action (window key, a cheat, or a combo)? Such keys
/// are swallowed by the hook so the same press never *also* triggers an
/// in-game action (e.g. a cheat bound to `G` would otherwise still throw a
/// grenade).
fn is_hud_bound(vk: u32) -> bool {
    if vk == 0 {
        return false;
    }
    if vk == TOGGLE_VK.load(Ordering::Relaxed) {
        return true;
    }
    ENGINE.get().and_then(|e| e.lock().ok().map(|g| g.hotkey_bound(vk))).unwrap_or(false)
}

/// Show/hide the N0xHUD window from the hook thread. Using `ShowWindow`
/// (rather than a viewport command) sidesteps Windows' foreground lock that
/// otherwise stops a background app from raising its own window, and works
/// without the egui loop running.
fn toggle_hud_window() {
    let title: Vec<u16> = "N0xHUD".encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let hwnd: HWND = FindWindowW(std::ptr::null(), title.as_ptr());
        if hwnd.is_null() {
            return;
        }
        if IsWindowVisible(hwnd) != 0 {
            ShowWindow(hwnd, SW_HIDE);
        } else {
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
        }
    }
}

unsafe extern "system" fn hook_proc(
    code: i32,
    wparam: windows_sys::Win32::Foundation::WPARAM,
    lparam: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::LRESULT {
    if code >= 0 {
        let msg = wparam as u32;
        let kb = unsafe { &*(lparam as *const KBDLLHOOKSTRUCT) };
        let vk = kb.vkCode;
        // Never treat our own synthesized combo keys (SendInput) as hotkeys —
        // that would be a feedback loop.
        let injected = (kb.flags & LLKHF_INJECTED) != 0;
        if !injected {
            let bound = is_hud_bound(vk);
            if msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN {
                let is_new = HELD
                    .lock()
                    .map(|mut held| {
                        if held.contains(&vk) {
                            false
                        } else {
                            held.push(vk);
                            true
                        }
                    })
                    .unwrap_or(false);
                if is_new {
                    handle_key_down(vk);
                }
            } else if (msg == WM_KEYUP || msg == WM_SYSKEYUP)
                && let Ok(mut held) = HELD.lock()
            {
                held.retain(|&k| k != vk);
            }
            if bound {
                // Swallow so the game never sees a key reserved for the HUD.
                return 1;
            }
        }
    }
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam) }
}

/// Install the hook on a dedicated thread with its own message loop (required
/// for `WH_KEYBOARD_LL` callbacks). `toggle_vk` is the window show/hide key.
pub fn spawn(toggle_vk: u32, engine: Arc<Mutex<Engine>>) {
    TOGGLE_VK.store(toggle_vk, Ordering::Relaxed);
    let _ = ENGINE.set(engine);
    thread::spawn(|| unsafe {
        let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), std::ptr::null_mut(), 0);
        if hook.is_null() {
            return;
        }
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    });
}
