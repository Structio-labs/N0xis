// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `input probe` — verify the actuation (write) path before building on it
//! (ROADMAP Phase 8, fixes RE_METHOD F4).
//!
//! The campaign built, shipped, and believed-working an entire input feature on
//! `SendInput` that **never once registered in the game** — because the game
//! filters injected input via the standard `LLKHF_INJECTED` check, and nobody
//! tested the write half independently before integrating it. A one-key probe
//! on day one would have caught it.
//!
//! This module *is* that probe. It installs its own low-level keyboard hook
//! (`WH_KEYBOARD_LL`) — the same vantage point a game's anti-injection filter
//! uses — then actuates a benign key through each injection method and reports,
//! per method, whether the event reached the OS input stack **and whether it
//! carries `LLKHF_INJECTED`**. That flag is the exact bit an injected-input
//! filter keys off: a method whose events carry it will be silently dropped by
//! any target that filters injected input. So the probe answers "will this
//! actuation method actually be seen?" *before* a feature is built on it.
//!
//! Honest scope: `SendInput` and `keybd_event` are actively exercised (they set
//! `LLKHF_INJECTED`, which is precisely why the campaign's input was ignored).
//! `Interception` (a kernel driver that produces *non*-injected input — the real
//! fix) and raw-HID injection require external drivers this tool does not bundle
//! or assume; the probe *detects their availability* and says so, rather than
//! pretending to drive a driver that may not be installed.

use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

use windows_sys::Win32::Foundation::{FreeLibrary, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, LoadLibraryW};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    keybd_event, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, PeekMessageW, SetWindowsHookExW, TranslateMessage,
    UnhookWindowsHookEx, KBDLLHOOKSTRUCT, LLKHF_INJECTED, MSG, PM_REMOVE, WH_KEYBOARD_LL,
    WM_KEYDOWN, WM_SYSKEYDOWN,
};

/// The default key the probe actuates: `VK_F15` (0x7E). Function keys F13–F24
/// are rarely bound by anything, so injecting one is about as side-effect-free
/// as a keystroke gets.
pub const DEFAULT_PROBE_VK: u16 = 0x7E;

// The hook callback is an `extern "system" fn` and can't capture, so it
// communicates through these process-wide atomics. The probe runs methods
// strictly one at a time, so there is never more than one in flight.
static WATCH_VK: AtomicU32 = AtomicU32::new(0);
static SAW_DOWN: AtomicBool = AtomicBool::new(false);
static SAW_INJECTED: AtomicBool = AtomicBool::new(false);

/// One method's probe result.
#[derive(Clone, Debug, Serialize)]
pub struct MethodResult {
    pub method: String,
    /// Whether the method is usable on this machine at all (a driver being
    /// present, an API existing). `false` methods are reported, not hidden.
    pub available: bool,
    /// Whether the OS input stack received the actuation (our hook saw it).
    /// `None` when the method wasn't exercised (unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered: Option<bool>,
    /// Whether the delivered event carried `LLKHF_INJECTED` — the bit a target
    /// filtering injected input keys off. `Some(true)` means "a game that
    /// filters injected input will ignore this method".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injected_flag: Option<bool>,
    /// `clean` (delivered, no injected flag → likely accepted), `injected-flag-set`
    /// (delivered but flagged → will be filtered), `not-delivered`, or
    /// `unavailable`.
    pub verdict: String,
    pub detail: String,
}

/// The full `n0xis.input.probe.v1` report.
#[derive(Clone, Debug, Serialize)]
pub struct ProbeReport {
    /// Virtual-key code actuated (hex-ish decimal).
    pub vk: u16,
    /// Optional target pid for context. Note: injected keystrokes go to the
    /// *foreground* window, so the probe is desktop-global — the pid is
    /// recorded for the operator's reference, not used to route input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub methods: Vec<MethodResult>,
    /// A one-line summary the operator should act on.
    pub recommendation: String,
}

unsafe extern "system" fn ll_keyboard_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // HC_ACTION == 0: the only code carrying a real key event.
    if code == 0 {
        let msg = wparam as u32;
        if msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN {
            let kb = unsafe { &*(lparam as *const KBDLLHOOKSTRUCT) };
            if kb.vkCode == WATCH_VK.load(Ordering::Relaxed) {
                SAW_DOWN.store(true, Ordering::Relaxed);
                if kb.flags & LLKHF_INJECTED != 0 {
                    SAW_INJECTED.store(true, Ordering::Relaxed);
                }
            }
        }
    }
    unsafe { CallNextHookEx(ptr::null_mut(), code, wparam, lparam) }
}

unsafe fn inject_send_input(vk: u16) {
    let make = |flags: u32| INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT { wVk: vk, wScan: 0, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    };
    let inputs = [make(0), make(KEYEVENTF_KEYUP)];
    unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), std::mem::size_of::<INPUT>() as i32) };
}

unsafe fn inject_keybd_event(vk: u16) {
    unsafe {
        keybd_event(vk as u8, 0, 0, 0);
        keybd_event(vk as u8, 0, KEYEVENTF_KEYUP, 0);
    }
}

/// Pump the thread's message queue (which is what dispatches the LL hook) until
/// the watched key is seen or `timeout` elapses; return `(delivered, injected)`.
unsafe fn drain_until_seen(timeout: Duration) -> (bool, bool) {
    let start = Instant::now();
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    while start.elapsed() < timeout {
        while unsafe { PeekMessageW(&mut msg, ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if SAW_DOWN.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    (SAW_DOWN.load(Ordering::Relaxed), SAW_INJECTED.load(Ordering::Relaxed))
}

unsafe fn probe_one(name: &str, vk: u16, timeout: Duration, inject: unsafe fn(u16)) -> MethodResult {
    WATCH_VK.store(vk as u32, Ordering::Relaxed);
    SAW_DOWN.store(false, Ordering::Relaxed);
    SAW_INJECTED.store(false, Ordering::Relaxed);
    unsafe { inject(vk) };
    let (delivered, injected) = unsafe { drain_until_seen(timeout) };

    let (verdict, detail) = if !delivered {
        (
            "not-delivered".to_string(),
            "the injected keystroke never reached the OS input stack — unexpected; check the session's UAC integrity level (an elevated foreground app blocks injection from a non-elevated probe)".to_string(),
        )
    } else if injected {
        (
            "injected-flag-set".to_string(),
            "delivered but carries LLKHF_INJECTED; a target filtering injected input (the standard game defense) will ignore it (RE_METHOD F4)".to_string(),
        )
    } else {
        (
            "clean".to_string(),
            "delivered with no LLKHF_INJECTED flag; likely accepted even by injected-input filters".to_string(),
        )
    };
    MethodResult {
        method: name.to_string(),
        available: true,
        delivered: Some(delivered),
        injected_flag: Some(injected),
        verdict,
        detail,
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Detect the Interception driver's user-mode DLL. Presence means the machine
/// *can* send non-injected input (the real fix for an injected-input filter);
/// absence is reported plainly rather than the method being hidden.
fn detect_interception() -> MethodResult {
    let name = to_wide("interception.dll");
    let handle = unsafe { LoadLibraryW(name.as_ptr()) };
    if !handle.is_null() {
        unsafe { FreeLibrary(handle) };
        MethodResult {
            method: "interception".into(),
            available: true,
            delivered: None,
            injected_flag: None,
            verdict: "available".into(),
            detail: "Interception driver DLL is present; it produces kernel-level input with no LLKHF_INJECTED flag — the fix when SendInput/keybd_event are filtered. Not exercised by this probe (it drives a physical-layer device).".into(),
        }
    } else {
        MethodResult {
            method: "interception".into(),
            available: false,
            delivered: None,
            injected_flag: None,
            verdict: "unavailable".into(),
            detail: "Interception driver not detected. Install it (github.com/oblitum/Interception) to send input that bypasses LLKHF_INJECTED filtering.".into(),
        }
    }
}

/// Raw-HID injection needs a virtual HID device (a gamepad/keyboard emulator
/// driver). We do not bundle or assume one; report it as needing setup rather
/// than claiming a capability we can't back.
fn detect_raw_hid() -> MethodResult {
    MethodResult {
        method: "raw_hid".into(),
        available: false,
        delivered: None,
        injected_flag: None,
        verdict: "unavailable".into(),
        detail: "Raw-HID injection requires a virtual HID device/driver (e.g. ViGEm for a gamepad, or a virtual-keyboard driver). None detected; not exercised.".into(),
    }
}

/// Run the full actuation probe. Installs an LL keyboard hook, exercises the
/// injection methods it can, detects the ones it can't, and returns a report.
/// `timeout_ms` bounds how long each exercised method waits for its event.
pub fn probe_actuation(vk: u16, pid: Option<u32>, timeout_ms: u32) -> Result<ProbeReport, String> {
    // Everything — hook install, injection, message pump, unhook — must happen
    // on one thread: an LL hook is dispatched only on the thread that installed
    // it, while that thread pumps its queue. A dedicated thread means the caller
    // needs no message loop of its own.
    let handle = std::thread::spawn(move || -> Result<Vec<MethodResult>, String> {
        unsafe {
            let hmod = GetModuleHandleW(ptr::null());
            let hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(ll_keyboard_hook), hmod, 0);
            if hook.is_null() {
                return Err("SetWindowsHookExW(WH_KEYBOARD_LL) failed — cannot observe injected input".into());
            }
            let timeout = Duration::from_millis(timeout_ms.max(1) as u64);
            let mut results = Vec::new();
            results.push(probe_one("send_input", vk, timeout, inject_send_input));
            results.push(probe_one("keybd_event", vk, timeout, inject_keybd_event));
            UnhookWindowsHookEx(hook);
            results.push(detect_interception());
            results.push(detect_raw_hid());
            Ok(results)
        }
    });
    let methods = handle.join().map_err(|_| "probe thread panicked".to_string())??;

    // Recommendation: if any exercised method delivered clean, name it; else if
    // everything delivered is flagged, point at the driver-based fix.
    let clean = methods.iter().find(|m| m.verdict == "clean");
    let any_flagged = methods.iter().any(|m| m.verdict == "injected-flag-set");
    let interception_ok = methods.iter().any(|m| m.method == "interception" && m.available);
    let recommendation = if let Some(m) = clean {
        format!("`{}` produces clean (non-injected) input — safe to build the write half on it.", m.method)
    } else if any_flagged && interception_ok {
        "SendInput/keybd_event are flagged LLKHF_INJECTED (a filtering target will ignore them). The Interception driver is present — route input through it.".into()
    } else if any_flagged {
        "SendInput/keybd_event are flagged LLKHF_INJECTED (a filtering target will ignore them). Install the Interception driver (or a virtual HID) before building on the write half — RE_METHOD F4.".into()
    } else {
        "No injection method delivered — investigate integrity level / foreground focus before trusting any write path.".into()
    };

    Ok(ProbeReport { vk, pid, methods, recommendation })
}
