//! Window enumeration, capture, and focus for the target process (ROADMAP
//! Phase 9 — agent target-selection tooling). This is the read-side helper an
//! AI agent uses to *see* the target and name a window before driving
//! `ui locate`: it does not itself hit-test memory.
//!
//! Scope and honesty (this is the whole point of the module):
//! - [`list_windows`] / [`window_rects`] / [`focus`] use only external Win32
//!   (`EnumWindows`, `GetWindowRect`, `DwmGetWindowAttribute`,
//!   `SetForegroundWindow`) — no injection, no messages beyond focus.
//! - [`screenshot`] captures via GDI (`BitBlt` from the window DC) and
//!   `PrintWindow(PW_RENDERFULLCONTENT)`. **These return a black frame for
//!   flip-model / DirectComposition DirectX windows** — which many modern games
//!   are. So the capture path is wrapped in a *blank-frame contract*
//!   ([`classify_frame`], the pre-flight checks): it never reports success on a
//!   blank image, and it distinguishes "capture blocked" / "window minimized" /
//!   "genuinely rendering black" with specific reason codes. The ideal path for
//!   flip-model targets (Windows.Graphics.Capture / DXGI Desktop Duplication)
//!   needs the heavy `windows` crate (WinRT/DXGI/D3D11 — windows-sys has none of
//!   it) and is a documented follow-on, not silently faked here.

use std::sync::Once;

use serde::Serialize;

use windows_sys::Win32::Foundation::{HWND, LPARAM, POINT, RECT};
use windows_sys::Win32::Graphics::Dwm::{
    DwmGetWindowAttribute, DWMWA_CLOAKED, DWMWA_EXTENDED_FRAME_BOUNDS,
};
use windows_sys::Win32::Graphics::Gdi::{
    BitBlt, ClientToScreen, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC,
    ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, DIB_RGB_COLORS,
    SRCCOPY,
};
use windows_sys::Win32::Storage::Xps::PrintWindow;
use windows_sys::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
use windows_sys::Win32::UI::HiDpi::{
    GetDpiForWindow, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, EnumWindows, GetClassNameW, GetClientRect, GetForegroundWindow,
    GetWindowDisplayAffinity, GetWindowLongPtrW, GetWindowRect, GetWindowTextW,
    GetWindowThreadProcessId, IsIconic, IsWindowVisible, SetForegroundWindow, ShowWindow, GWL_EXSTYLE,
    SW_RESTORE, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR, WS_EX_TOOLWINDOW,
};

/// `PW_RENDERFULLCONTENT` — undocumented (Win8.1+), not defined in windows-sys
/// (which only has `PW_CLIENTONLY = 1`). It is what makes `PrintWindow` capture
/// composited/DirectComposition content instead of returning blank.
const PW_RENDERFULLCONTENT: u32 = 0x0000_0002;
/// `PW_CLIENTONLY` — render only the client area (no title bar / border), so the
/// output aligns with the client-sized buffer we allocate. Without it,
/// `PrintWindow` renders the *whole window* into a client-sized bitmap, shifting
/// the content up-left and cropping the client's bottom-right.
const PW_CLIENTONLY: u32 = 0x0000_0001;

/// Set per-monitor-v2 DPI awareness once, before any window/DC call. Without
/// it, `GetWindowRect`/`BitBlt` get DPI-virtualized (lied-to) coordinates on a
/// scaled display, so a rect an agent picks maps to the wrong physical pixels —
/// a correctness bug for a tool whose whole job is choosing a screen rectangle.
/// Idempotent; safe to call at the top of every command.
pub fn ensure_dpi_aware() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        // Failure here is non-fatal (already set, or an old OS): the tool still
        // works, coordinates are just in the caller's virtualized space, which
        // `meta.coords` documents.
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    });
}

fn rect_arr(r: &RECT) -> [i32; 4] {
    [r.left, r.top, r.right, r.bottom]
}

/// The DWM-visible frame bounds (shadow excluded), or `None` before the window
/// has ever been shown / on failure — the caller falls back to `GetWindowRect`.
unsafe fn extended_frame(hwnd: HWND) -> Option<RECT> {
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    let hr = unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS as u32,
            &mut r as *mut RECT as *mut core::ffi::c_void,
            core::mem::size_of::<RECT>() as u32,
        )
    };
    (hr == 0).then_some(r)
}

unsafe fn is_cloaked(hwnd: HWND) -> bool {
    let mut cloaked: u32 = 0;
    let hr = unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED as u32,
            &mut cloaked as *mut u32 as *mut core::ffi::c_void,
            core::mem::size_of::<u32>() as u32,
        )
    };
    hr == 0 && cloaked != 0
}

unsafe fn read_wstr(f: impl Fn(*mut u16, i32) -> i32) -> String {
    let mut buf = [0u16; 512];
    let n = f(buf.as_mut_ptr(), buf.len() as i32);
    if n <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..n as usize])
}

/// Client area expressed in screen coordinates (`GetClientRect` gives size with
/// origin 0; `ClientToScreen` maps the origin). This is "where the game
/// actually renders", shadow- and border-free.
unsafe fn client_rect_screen(hwnd: HWND) -> Option<RECT> {
    let mut c = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    if unsafe { GetClientRect(hwnd, &mut c) } == 0 {
        return None;
    }
    let mut origin = POINT { x: 0, y: 0 };
    if unsafe { ClientToScreen(hwnd, &mut origin) } == 0 {
        return None;
    }
    Some(RECT {
        left: origin.x,
        top: origin.y,
        right: origin.x + (c.right - c.left),
        bottom: origin.y + (c.bottom - c.top),
    })
}

/// One enumerated top-level window belonging to the target process.
#[derive(Clone, Debug, Serialize)]
pub struct WindowInfo {
    /// HWND as an integer, for JSON round-tripping and passing back to `focus`.
    pub hwnd: usize,
    pub pid: u32,
    pub title: String,
    pub class: String,
    pub visible: bool,
    pub minimized: bool,
    pub cloaked: bool,
    pub tool_window: bool,
    /// Raw `GetWindowRect` — shadow-inflated on Win10+; kept for debugging.
    pub rect_window: [i32; 4],
    /// `DWMWA_EXTENDED_FRAME_BOUNDS` — the canonical visible bounds for
    /// capture/input. `None` before the window's first show.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rect_frame: Option<[i32; 4]>,
    /// Client area in screen coordinates — where the game renders.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rect_client: Option<[i32; 4]>,
    /// Per-window DPI (`GetDpiForWindow`); 96 == 100% scaling.
    pub dpi: u32,
    /// Width×height of `rect_frame` (or `rect_window`); the "how big on screen".
    pub width: i32,
    pub height: i32,
}

struct EnumCtx {
    pid: u32,
    out: Vec<HWND>,
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> i32 {
    // Must never unwind across the FFI boundary — keep this body panic-free.
    let ctx = unsafe { &mut *(lparam as *mut EnumCtx) };
    let mut wpid: u32 = 0;
    unsafe { GetWindowThreadProcessId(hwnd, &mut wpid) };
    if wpid == ctx.pid {
        ctx.out.push(hwnd);
    }
    1 // TRUE — keep enumerating
}

/// Every top-level window owned by `pid`, largest visible first. Includes
/// hidden/tool/cloaked windows (flagged), so a caller can see the full picture,
/// but ordering puts the most likely "the game window" at the front.
pub fn list_windows(pid: u32) -> Vec<WindowInfo> {
    ensure_dpi_aware();
    let mut ctx = EnumCtx { pid, out: Vec::new() };
    unsafe {
        EnumWindows(Some(enum_proc), &mut ctx as *mut EnumCtx as LPARAM);
    }
    let mut infos: Vec<WindowInfo> = ctx
        .out
        .into_iter()
        .map(|hwnd| unsafe {
            let mut wr = RECT { left: 0, top: 0, right: 0, bottom: 0 };
            GetWindowRect(hwnd, &mut wr);
            let frame = extended_frame(hwnd);
            let client = client_rect_screen(hwnd);
            let bounds = frame.as_ref().unwrap_or(&wr);
            let ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
            WindowInfo {
                hwnd: hwnd as usize,
                pid,
                title: read_wstr(|p, n| GetWindowTextW(hwnd, p, n)),
                class: read_wstr(|p, n| GetClassNameW(hwnd, p, n)),
                visible: IsWindowVisible(hwnd) != 0,
                minimized: IsIconic(hwnd) != 0,
                cloaked: is_cloaked(hwnd),
                tool_window: (ex_style as u32 & WS_EX_TOOLWINDOW) != 0,
                rect_window: rect_arr(&wr),
                rect_frame: frame.as_ref().map(rect_arr),
                rect_client: client.as_ref().map(rect_arr),
                dpi: GetDpiForWindow(hwnd),
                width: bounds.right - bounds.left,
                height: bounds.bottom - bounds.top,
            }
        })
        .collect();

    // Most-likely-first: visible, non-tool, non-cloaked, then by area.
    infos.sort_by(|a, b| {
        let score = |w: &WindowInfo| -> (bool, bool, bool, i64) {
            (w.visible && !w.minimized, !w.tool_window, !w.cloaked, (w.width as i64) * (w.height as i64))
        };
        score(b).cmp(&score(a))
    });
    infos
}

/// The process id that owns `hwnd` (0 if the handle is invalid). Lets a caller
/// verify an explicitly-supplied HWND actually belongs to the pid it named,
/// rather than trusting it blindly.
pub fn window_pid(hwnd: usize) -> u32 {
    let mut pid: u32 = 0;
    unsafe { GetWindowThreadProcessId(hwnd as HWND, &mut pid) };
    pid
}

/// Pick the best "the game window" for a pid: the largest visible, non-tool,
/// non-cloaked, non-minimized window. `None` if the process has no such window.
pub fn best_window(pid: u32) -> Option<WindowInfo> {
    list_windows(pid)
        .into_iter()
        .find(|w| w.visible && !w.minimized && !w.tool_window && !w.cloaked && w.width > 0 && w.height > 0)
}

// ----------------------------------------------------------------------------
// Focus
// ----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct FocusResult {
    pub hwnd: usize,
    /// Whether the window is the foreground window *after* the attempt
    /// (the only trustworthy success signal — `SetForegroundWindow`'s return
    /// lies, it often only flashes the taskbar button).
    pub foreground: bool,
    /// What was tried, in order.
    pub method: String,
}

/// Bring `hwnd` to the foreground. Uses the `AttachThreadInput` workaround (no
/// injection) to satisfy the "received the last input event" rule; verifies
/// with `GetForegroundWindow` rather than trusting the return value. Does not
/// synthesize input (that can leak a stray keypress into the user's session) —
/// callers wanting that escalation gate it themselves.
pub fn focus(hwnd: usize) -> FocusResult {
    ensure_dpi_aware();
    let hwnd = hwnd as HWND;
    unsafe {
        if IsIconic(hwnd) != 0 {
            ShowWindow(hwnd, SW_RESTORE);
        }
        if GetForegroundWindow() == hwnd {
            return FocusResult { hwnd: hwnd as usize, foreground: true, method: "already-foreground".into() };
        }
        let cur = GetCurrentThreadId();
        let fg = GetForegroundWindow();
        let tgt = if fg.is_null() { 0 } else { GetWindowThreadProcessId(fg, core::ptr::null_mut()) };
        let attached = tgt != 0 && tgt != cur && AttachThreadInput(cur, tgt, 1) != 0;
        BringWindowToTop(hwnd);
        let set = SetForegroundWindow(hwnd) != 0;
        if attached {
            // Always detach immediately — a held attachment serializes both
            // input queues and can deadlock.
            AttachThreadInput(cur, tgt, 0);
        }
        let foreground = GetForegroundWindow() == hwnd;
        FocusResult {
            hwnd: hwnd as usize,
            foreground,
            method: if attached { "attach-thread-input" } else if set { "set-foreground" } else { "denied" }.into(),
        }
    }
}

// ----------------------------------------------------------------------------
// Screenshot (GDI + PrintWindow, with the blank-frame contract)
// ----------------------------------------------------------------------------

/// Which capture path produced (or was tried for) a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMethod {
    /// `BitBlt` from the window's own DC — cheapest, immune to occlusion,
    /// correct for legacy blt-model swapchains; blank for flip-model/DComp.
    WindowDc,
    /// `PrintWindow(PW_RENDERFULLCONTENT)` — captures composited content, but
    /// makes the target's UI thread render (a soft disturbance) and is blank
    /// for pure flip-model swapchains.
    PrintWindow,
}

/// Verdict from the pixel analysis — never "the API returned success".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameVerdict {
    /// Real content.
    Ok,
    /// Low-entropy but non-uniform — returned, but flagged low-confidence.
    Suspect,
    /// max_luma≈0 or ~all-black.
    BlankBlack,
    /// Near-constant color (cleared-but-not-presented surface).
    BlankUniform,
}

#[derive(Clone, Debug, Serialize)]
pub struct FrameStats {
    pub max_luma: u8,
    pub mean_luma: f32,
    pub frac_exact_black: f32,
    pub distinct_colors_5bit: u32,
    pub verdict: FrameVerdict,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaptureAttempt {
    pub method: CaptureMethod,
    pub stats: FrameStats,
}

/// The outcome of a capture. On a good frame `png` holds the encoded image and
/// `blank` is false; on a blank/blocked frame `png` still holds the (diagnostic)
/// image if one was produced, `blank` is true, and `reason` explains why.
#[derive(Debug)]
pub struct Screenshot {
    pub width: u32,
    pub height: u32,
    /// RGBA8, top-down, alpha forced to 255. Empty if no frame was produced
    /// (a hard pre-flight failure).
    pub rgba: Vec<u8>,
    pub method: Option<CaptureMethod>,
    pub blank: bool,
    /// The winning (or, when blank, last-tried) frame's verdict. `Suspect` here
    /// with `blank == false` means a low-confidence near-blank frame was
    /// returned — a caller must treat a rect picked from it with suspicion, not
    /// as a crisp capture.
    pub verdict: FrameVerdict,
    /// Machine-readable reason on a non-OK result (`window_minimized`,
    /// `capture_blocked_by_display_affinity`, `blank_black`, `all_methods_blank`…).
    pub reason: Option<String>,
    pub attempts: Vec<CaptureAttempt>,
    /// The window's client rect in screen coords at capture time — so a rect
    /// chosen from this image maps back cleanly.
    pub client_rect: Option<[i32; 4]>,
    pub dpi: u32,
}

/// Luma-based blank/uniform classifier over a decimated pixel grid (brief-
/// derived thresholds). Runs on the returned RGBA (alpha already forced).
pub fn classify_frame(rgba: &[u8], width: u32, height: u32) -> FrameStats {
    let (w, h) = (width as usize, height as usize);
    let mut max_luma = 0u8;
    let mut sum_luma = 0f64;
    let mut n = 0u64;
    let mut exact_black = 0u64;
    let mut colors = vec![0u64; 32768 / 64]; // 5-bit-per-channel presence bitset
    let step = 8usize; // decimate
    let mut y = 0;
    while y < h {
        let mut x = 0;
        while x < w {
            let i = (y * w + x) * 4;
            if i + 3 < rgba.len() {
                let (r, g, b) = (rgba[i], rgba[i + 1], rgba[i + 2]);
                let luma = (0.2126 * r as f32 + 0.7152 * g as f32 + 0.0722 * b as f32) as u8;
                max_luma = max_luma.max(luma);
                sum_luma += luma as f64;
                if r == 0 && g == 0 && b == 0 {
                    exact_black += 1;
                }
                let key = ((r as usize >> 3) << 10) | ((g as usize >> 3) << 5) | (b as usize >> 3);
                colors[key / 64] |= 1u64 << (key % 64);
                n += 1;
            }
            x += step;
        }
        y += step;
    }
    let n = n.max(1);
    let distinct: u32 = colors.iter().map(|w| w.count_ones()).sum();
    let frac_exact_black = (exact_black as f64 / n as f64) as f32;
    let mean_luma = (sum_luma / n as f64) as f32;
    let verdict = if max_luma <= 2 || frac_exact_black >= 0.999 {
        FrameVerdict::BlankBlack
    } else if distinct <= 2 {
        FrameVerdict::BlankUniform
    } else if distinct < 16 {
        FrameVerdict::Suspect
    } else {
        FrameVerdict::Ok
    };
    FrameStats { max_luma, mean_luma, frac_exact_black, distinct_colors_5bit: distinct, verdict }
}

/// Errors that abort a capture before any frame is produced.
#[derive(Debug)]
pub struct CaptureError {
    pub reason: String,
}

/// Capture `hwnd`'s client area. Tries `methods` in order and returns the first
/// frame that classifies `Ok`/`Suspect`; if all are blank, returns the last
/// frame with `blank=true` and a reason, plus every attempt's stats. Honest by
/// construction: a blank capture is *never* presented as a good one.
pub fn screenshot(hwnd: usize, methods: &[CaptureMethod]) -> Result<Screenshot, CaptureError> {
    ensure_dpi_aware();
    let hwnd = hwnd as HWND;

    // --- Pre-flight: turn "mysteriously black" into a specific diagnosis. ---
    unsafe {
        if IsWindowVisible(hwnd) == 0 {
            return Err(CaptureError { reason: "window_not_visible".into() });
        }
        if IsIconic(hwnd) != 0 {
            return Err(CaptureError { reason: "window_minimized".into() });
        }
        if is_cloaked(hwnd) {
            return Err(CaptureError { reason: "window_cloaked".into() });
        }
        let mut affinity: u32 = 0;
        if GetWindowDisplayAffinity(hwnd, &mut affinity) != 0
            && (affinity == WDA_MONITOR || affinity == WDA_EXCLUDEFROMCAPTURE)
        {
            return Err(CaptureError { reason: "capture_blocked_by_display_affinity".into() });
        }
    }

    // Capture the client area (not the shadow-inflated window rect).
    let client = unsafe { client_rect_screen(hwnd) };
    let (cw, ch) = match &client {
        Some(r) if r.right > r.left && r.bottom > r.top => ((r.right - r.left) as u32, (r.bottom - r.top) as u32),
        _ => return Err(CaptureError { reason: "window_offscreen_or_degenerate".into() }),
    };
    let dpi = unsafe { GetDpiForWindow(hwnd) };

    let mut attempts = Vec::new();
    let mut last: Option<(CaptureMethod, Vec<u8>, FrameVerdict)> = None;

    let mut suspect: Option<(CaptureMethod, Vec<u8>)> = None;
    for &method in methods {
        let Some(rgba) = (unsafe { capture_one(hwnd, method, cw, ch) }) else {
            continue;
        };
        let stats = classify_frame(&rgba, cw, ch);
        let verdict = stats.verdict;
        attempts.push(CaptureAttempt { method, stats });
        match verdict {
            // A crisp frame — return immediately.
            FrameVerdict::Ok => {
                return Ok(Screenshot {
                    width: cw,
                    height: ch,
                    rgba,
                    method: Some(method),
                    blank: false,
                    verdict,
                    reason: None,
                    attempts,
                    client_rect: client.as_ref().map(rect_arr),
                    dpi,
                });
            }
            // Low-confidence near-blank — keep it only as a fallback and try the
            // remaining methods first, in case one produces a clean `Ok` frame.
            FrameVerdict::Suspect => {
                if suspect.is_none() {
                    suspect = Some((method, rgba));
                }
            }
            FrameVerdict::BlankBlack | FrameVerdict::BlankUniform => {
                last = Some((method, rgba, verdict));
            }
        }
    }

    // No `Ok` frame. Prefer a `Suspect` fallback (returned with blank:false but
    // verdict:Suspect, so the caller can flag low confidence) over a blank one.
    if let Some((method, rgba)) = suspect {
        return Ok(Screenshot {
            width: cw,
            height: ch,
            rgba,
            method: Some(method),
            blank: false,
            verdict: FrameVerdict::Suspect,
            reason: Some("low_confidence".into()),
            attempts,
            client_rect: client.as_ref().map(rect_arr),
            dpi,
        });
    }

    // Every method was blank. Return the last frame as a diagnostic artifact,
    // clearly marked blank, with the aggregate reason.
    match last {
        Some((method, rgba, verdict)) => Ok(Screenshot {
            width: cw,
            height: ch,
            rgba,
            method: Some(method),
            blank: true,
            verdict,
            reason: Some("all_methods_blank".into()),
            attempts,
            client_rect: client.as_ref().map(rect_arr),
            dpi,
        }),
        None => Err(CaptureError { reason: "no_frame_produced".into() }),
    }
}

/// One capture attempt into a fresh top-down BGRA DIB; returns RGBA8 with alpha
/// forced to 255, or `None` if the GDI calls failed. `unsafe`: raw GDI handles,
/// all released on every path.
unsafe fn capture_one(hwnd: HWND, method: CaptureMethod, w: u32, h: u32) -> Option<Vec<u8>> {
    unsafe {
        // Source DC. `GetDC(hwnd)` returns a **client-area** DC (origin at the
        // client top-left), which is what aligns with our client-sized buffer —
        // `GetWindowDC` would put the origin at the window frame and capture the
        // title bar/border instead. For PrintWindow we render into the memory DC
        // directly and only need a reference DC to create a compatible one; use
        // the screen DC for that.
        let src_dc = match method {
            CaptureMethod::WindowDc => GetDC(hwnd),
            CaptureMethod::PrintWindow => GetDC(core::ptr::null_mut()),
        };
        if src_dc.is_null() {
            return None;
        }
        let mem_dc = CreateCompatibleDC(src_dc);
        if mem_dc.is_null() {
            release_dc(hwnd, method, src_dc);
            return None;
        }

        let mut bmi: BITMAPINFO = core::mem::zeroed();
        bmi.bmiHeader = BITMAPINFOHEADER {
            biSize: core::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w as i32,
            biHeight: -(h as i32), // negative = top-down
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB as u32,
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        };
        let mut bits: *mut core::ffi::c_void = core::ptr::null_mut();
        let dib = CreateDIBSection(mem_dc, &bmi, DIB_RGB_COLORS, &mut bits, core::ptr::null_mut(), 0);
        if dib.is_null() || bits.is_null() {
            // A non-null handle with a null bits pointer would still leak the
            // bitmap without this.
            if !dib.is_null() {
                DeleteObject(dib);
            }
            DeleteDC(mem_dc);
            release_dc(hwnd, method, src_dc);
            return None;
        }
        let old = SelectObject(mem_dc, dib);

        let ok = match method {
            CaptureMethod::WindowDc => {
                // `src_dc` is the client-area DC (see above), so its (0,0) is the
                // client top-left — BitBlt the client-sized region straight out.
                // CAPTUREBLT pulls layered content too.
                BitBlt(mem_dc, 0, 0, w as i32, h as i32, src_dc, 0, 0, SRCCOPY | CAPTUREBLT) != 0
            }
            // PW_CLIENTONLY so the client area (not the whole window) is rendered
            // into our client-sized buffer, aligned; PW_RENDERFULLCONTENT so
            // composited content is captured rather than a blank WM_PRINT.
            CaptureMethod::PrintWindow => {
                PrintWindow(hwnd, mem_dc, PW_RENDERFULLCONTENT | PW_CLIENTONLY) != 0
            }
        };

        let result = if ok {
            // Copy out of the DIB before tearing it down.
            let n = (w as usize) * (h as usize) * 4;
            let src = core::slice::from_raw_parts(bits as *const u8, n);
            let mut rgba = Vec::with_capacity(n);
            // BGRA -> RGBA, force alpha 255 (GDI leaves alpha 0 -> transparent
            // -> renders black; the #1 self-inflicted false-black).
            let mut i = 0;
            while i + 3 < n {
                rgba.push(src[i + 2]); // R
                rgba.push(src[i + 1]); // G
                rgba.push(src[i]); // B
                rgba.push(255); // A
                i += 4;
            }
            Some(rgba)
        } else {
            None
        };

        SelectObject(mem_dc, old);
        DeleteObject(dib);
        DeleteDC(mem_dc);
        release_dc(hwnd, method, src_dc);
        result
    }
}

unsafe fn release_dc(hwnd: HWND, method: CaptureMethod, dc: windows_sys::Win32::Graphics::Gdi::HDC) {
    unsafe {
        match method {
            CaptureMethod::WindowDc => {
                ReleaseDC(hwnd, dc);
            }
            CaptureMethod::PrintWindow => {
                ReleaseDC(core::ptr::null_mut(), dc);
            }
        }
    }
}

/// Minimal, dependency-free standard-alphabet base64 (padded) — for embedding a
/// captured PNG in the `{ok,data,meta}` envelope when a caller has no
/// filesystem access. Shared by both frontends so the encoding can't diverge.
pub fn b64_encode(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Encode RGBA8 as a PNG byte stream.
#[cfg(feature = "live")]
pub fn encode_png(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, width, height);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().map_err(|e| e.to_string())?;
        writer.write_image_data(rgba).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_all_black_is_blank_black() {
        let rgba = vec![0u8; 16 * 16 * 4];
        let s = classify_frame(&rgba, 16, 16);
        assert_eq!(s.verdict, FrameVerdict::BlankBlack);
    }

    #[test]
    fn classify_solid_color_is_blank_uniform() {
        // Solid mid-grey, alpha 255 — not black, but useless.
        let mut rgba = Vec::new();
        for _ in 0..(16 * 16) {
            rgba.extend_from_slice(&[128, 128, 128, 255]);
        }
        let s = classify_frame(&rgba, 16, 16);
        assert_eq!(s.verdict, FrameVerdict::BlankUniform, "got {s:?}");
        assert!(s.max_luma > 2, "not black, just uniform");
    }

    #[test]
    fn classify_rich_content_is_ok() {
        // A gradient/noise-ish pattern with many distinct colors.
        let (w, h) = (64u32, 64u32);
        let mut rgba = Vec::new();
        for y in 0..h {
            for x in 0..w {
                rgba.extend_from_slice(&[(x * 4) as u8, (y * 4) as u8, ((x + y) * 2) as u8, 255]);
            }
        }
        let s = classify_frame(&rgba, w, h);
        assert_eq!(s.verdict, FrameVerdict::Ok, "got {s:?}");
    }

    #[test]
    fn png_roundtrips_dimensions() {
        let rgba = vec![255u8; 8 * 8 * 4];
        let png = encode_png(&rgba, 8, 8).unwrap();
        // PNG signature + it decodes back to 8x8.
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
        let decoder = png::Decoder::new(std::io::Cursor::new(&png));
        let reader = decoder.read_info().unwrap();
        assert_eq!(reader.info().width, 8);
        assert_eq!(reader.info().height, 8);
    }
}
