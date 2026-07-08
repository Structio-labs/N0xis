//! Win32 debug API: software breakpoint + wait for first hit (AI-oriented `await-hit`).

use crate::{
    detect_arch, find_module, parse_hex_u64, resolve_pid, stderr_progress, ModuleInfo, OutputMode,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT, GetLastError,
    HANDLE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    FlushInstructionCache, GetThreadContext, ReadProcessMemory, SetThreadContext, WaitForDebugEvent,
    WriteProcessMemory, CONTEXT, CONTEXT_FULL_AMD64, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenThread, PROCESS_ALL_ACCESS, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_SET_CONTEXT,
};

const POLL_MS: u32 = 250;

#[inline]
fn wait_debug_poll_timed_out(err: u32) -> bool {
    // `WAIT_TIMEOUT`; some kernels report `ERROR_SEM_TIMEOUT` (121) instead.
    err == windows_sys::Win32::Foundation::WAIT_TIMEOUT || err == 121
}

pub(crate) struct AwaitHitArgs {
    pub pid: Option<u32>,
    pub module: String,
    pub addr_rva: bool,
    pub addr: String,
    pub instruction: Option<String>,
    pub instruction_file: Option<std::path::PathBuf>,
    pub timeout_ms: u64,
    pub stack_qwords: usize,
    pub report: Option<std::path::PathBuf>,
}

pub(crate) fn handle_await_hit(args: AwaitHitArgs, out: &OutputMode, start: Instant) -> Result<()> {
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (args, out, start);
        bail!("`debug await-hit` is only built for Windows x86_64 targets.");
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        await_hit_impl(args, out, start)
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn await_hit_impl(args: AwaitHitArgs, out: &OutputMode, start: Instant) -> Result<()> {
    let pid = resolve_pid(args.pid)?;
    let arch = detect_arch(pid)?;
    if arch != "x64" {
        bail!("`debug await-hit` requires a 64-bit target process (got arch={arch}).");
    }

    let module = find_module(pid, &args.module)?;
    let base = parse_hex_u64(&module.base_address)?;
    let addr_val = parse_hex_u64(&args.addr)?;
    let rva_input = args.addr_rva.then_some(addr_val);
    let bp_va = if args.addr_rva {
        base.saturating_add(addr_val)
    } else {
        addr_val
    };

    let await_user = load_instruction(&args.instruction, args.instruction_file.as_deref())?;

    let h_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if h_process.is_null() {
        bail!(
            "OpenProcess(PROCESS_ALL_ACCESS) failed for pid={pid}. Try elevated n0x or close other debuggers."
        );
    }

    let mut report_file: Option<std::io::BufWriter<std::fs::File>> = None;
    if let Some(ref p) = args.report {
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("report: create dir {}", parent.display()))?;
            }
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(p)
            .with_context(|| format!("report: open {}", p.display()))?;
        report_file = Some(std::io::BufWriter::new(f));
    }

    let write_report = |w: &mut Option<std::io::BufWriter<std::fs::File>>, v: &Value| -> Result<()> {
        match w {
            Some(bw) => {
                serde_json::to_writer(&mut *bw, v)?;
                bw.write_all(b"\n")?;
                bw.flush()?;
                Ok(())
            }
            None => Ok(()),
        }
    };

    let header = json!({
        "schema": "n0x.debug.await_hit.report.v1",
        "kind": "session_start",
        "pid": pid,
        "module": args.module,
        "breakpointVa": format!("0x{bp_va:X}"),
        "addrRva": rva_input.map(|r| format!("0x{r:X}")),
        "timeoutMs": args.timeout_ms,
    });
    write_report(&mut report_file, &header)?;

    let mut orig_byte: u8 = 0;
    let mut patched: bool;

    unsafe {
        let mut sz = 0usize;
        if ReadProcessMemory(
            h_process,
            bp_va as *const _,
            (&mut orig_byte) as *mut u8 as *mut _,
            1,
            &mut sz,
        ) == 0
            || sz != 1
        {
            let _ = CloseHandle(h_process);
            bail!("ReadProcessMemory failed at breakpoint VA 0x{bp_va:X}");
        }

        let cc: u8 = 0xCC;
        if WriteProcessMemory(
            h_process,
            bp_va as *mut _,
            (&cc) as *const u8 as *const _,
            1,
            &mut sz,
        ) == 0
            || sz != 1
        {
            let _ = CloseHandle(h_process);
            bail!("WriteProcessMemory (int3) failed at 0x{bp_va:X}");
        }
        patched = true;
        if FlushInstructionCache(h_process, bp_va as *const _, 1) == 0 {
            // non-fatal on some kernels
        }
    }

    if unsafe { DebugActiveProcess(pid) } == 0 {
        restore_byte_safe(h_process, bp_va, orig_byte)?;
        unsafe { CloseHandle(h_process) };
        bail!(
            "DebugActiveProcess failed for pid={pid}. Process may already be under another debugger, or access denied."
        );
    }

    // Must be called *after* the process is debugging this target (successful DebugActiveProcess).
    if unsafe { DebugSetProcessKillOnExit(0) } == 0 {
        let _ = unsafe { DebugActiveProcessStop(pid) };
        restore_byte_safe(h_process, bp_va, orig_byte)?;
        unsafe {
            CloseHandle(h_process);
        }
        bail!("DebugSetProcessKillOnExit(false) failed");
    }

    stderr_progress(out, "`debug await-hit`: waiting for EXCEPTION_BREAKPOINT …");
    if let Some(ref t) = await_user {
        stderr_progress(out, &format!("user action → {t}"));
    }

    let awaiting_evt = json!({
        "schema": "n0x.debug.await_hit.report.v1",
        "kind": "awaiting_user",
        "awaitUser": await_user.clone(),
        "breakpointVa": format!("0x{bp_va:X}"),
    });
    write_report(&mut report_file, &awaiting_evt)?;

    let deadline_wait = Instant::now() + Duration::from_millis(args.timeout_ms.max(1));
    let mut hit_json: Option<Value> = None;
    let mut timed_out = false;

    loop {
        if Instant::now() >= deadline_wait {
            timed_out = true;
            break;
        }
        let mut ev = DEBUG_EVENT::default();
        let wt = POLL_MS.min(
            deadline_wait
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(u128::from(u32::MAX)) as u32,
        )
        .max(1);

        let r = unsafe { WaitForDebugEvent(&mut ev, wt) };
        if r == 0 {
            let err = unsafe { GetLastError() };
            if wait_debug_poll_timed_out(err) {
                continue;
            }
            let _ = unsafe { DebugActiveProcessStop(pid) };
            if patched {
                let _ = restore_byte_safe(h_process, bp_va, orig_byte);
            }
            unsafe { CloseHandle(h_process) };
            bail!("WaitForDebugEvent failed: GetLastError={err}");
        }

        let ev_pid = ev.dwProcessId;
        let ev_tid = ev.dwThreadId;

        if ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let info = unsafe { ev.u.Exception };
            let code = info.ExceptionRecord.ExceptionCode;
            let addr = info.ExceptionRecord.ExceptionAddress as usize as u64;
            let first_chance = info.dwFirstChance;

            if code == EXCEPTION_BREAKPOINT
                && addr == bp_va
                && first_chance != 0
            {
                let hit = capture_hit(
                    pid,
                    ev_tid,
                    h_process,
                    bp_va,
                    orig_byte,
                    &module,
                    base,
                    args.stack_qwords,
                )?;

                restore_byte_safe(h_process, bp_va, orig_byte)?;
                patched = false;
                unsafe {
                    FlushInstructionCache(h_process, bp_va as *const _, 1);
                }

                // After `int3`, `Rip` is past the patch byte; we restored only the first byte of a
                // possibly multi-byte instruction — must re-run from `bp_va` or the game mis-decodes.
                rewind_rip_to_breakpoint(ev_tid, bp_va)?;

                unsafe {
                    ContinueDebugEvent(ev_pid, ev_tid, DBG_CONTINUE);
                }
                let drain_deadline = Instant::now() + Duration::from_millis(250);
                while Instant::now() < drain_deadline {
                    let mut ev2 = DEBUG_EVENT::default();
                    if unsafe { WaitForDebugEvent(&mut ev2, 50) } == 0 {
                        let e2 = unsafe { GetLastError() };
                        if wait_debug_poll_timed_out(e2) {
                            break;
                        }
                        break;
                    }
                    unsafe {
                        ContinueDebugEvent(ev2.dwProcessId, ev2.dwThreadId, DBG_CONTINUE);
                    }
                }

                hit_json = Some(hit);
                break;
            }
            unsafe {
                ContinueDebugEvent(
                    ev_pid,
                    ev_tid,
                    if code == EXCEPTION_BREAKPOINT {
                        DBG_EXCEPTION_NOT_HANDLED
                    } else {
                        DBG_CONTINUE
                    },
                );
            };
            continue;
        }

        unsafe {
            ContinueDebugEvent(ev_pid, ev_tid, DBG_CONTINUE);
        };
    }

    let _ignore = unsafe { DebugActiveProcessStop(pid) };

    if patched {
        let _ = restore_byte_safe(h_process, bp_va, orig_byte);
    }
    unsafe { CloseHandle(h_process) };

    if timed_out || hit_json.is_none() {
        let footer = json!({
            "schema": "n0x.debug.await_hit.report.v1",
            "kind": "timeout",
            "timedOut": true,
            "timeoutMs": args.timeout_ms,
        });
        write_report(&mut report_file, &footer)?;

        crate::emit_success(
            out,
            json!({
                "schema": "n0x.debug.await_hit.v1",
                "pid": pid,
                "module": args.module,
                "breakpointVa": format!("0x{bp_va:X}"),
                "addrRva": rva_input.map(|r| format!("0x{r:X}")),
                "timedOut": true,
                "awaitUser": await_user,
                "hit": serde_json::Value::Null,
                "reportPath": args.report.as_ref().map(|p| p.display().to_string()),
            }),
            start,
            Some(pid),
        );
        return Ok(());
    }

    let hit = hit_json.unwrap();
    let footer_hit = json!({
        "schema": "n0x.debug.await_hit.report.v1",
        "kind": "hit",
        "hit": &hit,
    });
    write_report(&mut report_file, &footer_hit)?;

    crate::emit_success(
        out,
        json!({
            "schema": "n0x.debug.await_hit.v1",
            "pid": pid,
            "module": args.module,
            "breakpointVa": format!("0x{bp_va:X}"),
            "addrRva": rva_input.map(|r| format!("0x{r:X}")),
            "timedOut": false,
            "awaitUser": await_user,
            "hit": hit,
            "reportPath": args.report.as_ref().map(|p| p.display().to_string()),
        }),
        start,
        Some(pid),
    );
    Ok(())
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn capture_hit(
    _pid: u32,
    tid: u32,
    h_process: HANDLE,
    bp_va: u64,
    _orig_byte: u8,
    module: &ModuleInfo,
    base: u64,
    stack_qwords: usize,
) -> Result<Value> {
    let h_thread = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, 0, tid) };
    if h_thread.is_null() {
        bail!("OpenThread failed for tid={tid}");
    }

    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    let ok = unsafe { GetThreadContext(h_thread, &mut ctx as *mut _) };
    unsafe { CloseHandle(h_thread) };
    if ok == 0 {
        bail!("GetThreadContext failed");
    }

    let rip = ctx.Rip;
    let rsp = ctx.Rsp;

    let strip = module.name.strip_suffix(".dll").unwrap_or(&module.name);
    let relative_rip = if rip >= base && rip < base + module.size {
        Some(format!(
            "{}+{:X}",
            strip,
            rip.saturating_sub(base)
        ))
    } else {
        None
    };

    let mut stack_slots: Vec<String> = Vec::new();
    let n = stack_qwords.min(512);
    if n > 0 && rsp != 0 {
        let sz = n.saturating_mul(8);
        let mut buf = vec![0u8; sz];
        let mut rd = 0usize;
        let ok_mem = unsafe {
            ReadProcessMemory(
                h_process,
                rsp as *const _,
                buf.as_mut_ptr() as *mut _,
                sz,
                &mut rd,
            )
        };
        if ok_mem != 0 && rd >= 8 {
            for i in (0..rd).step_by(8) {
                let q =
                    u64::from_le_bytes(buf[i..i + 8].try_into().unwrap_or([0u8; 8]));
                stack_slots.push(format!("0x{q:X}"));
            }
        }
    }

    Ok(json!({
        "schema": "n0x.debug.hit.v1",
        "threadId": tid,
        "breakpointVa": format!("0x{bp_va:X}"),
        "rip": format!("0x{rip:X}"),
        "rsp": format!("0x{rsp:X}"),
        "relativeRip": relative_rip,
        "registers": {
            "rax": format!("0x{:X}", ctx.Rax),
            "rbx": format!("0x{:X}", ctx.Rbx),
            "rcx": format!("0x{:X}", ctx.Rcx),
            "rdx": format!("0x{:X}", ctx.Rdx),
            "rsi": format!("0x{:X}", ctx.Rsi),
            "rdi": format!("0x{:X}", ctx.Rdi),
            "r8": format!("0x{:X}", ctx.R8),
            "r9": format!("0x{:X}", ctx.R9),
            "r10": format!("0x{:X}", ctx.R10),
            "r11": format!("0x{:X}", ctx.R11),
            "r12": format!("0x{:X}", ctx.R12),
            "r13": format!("0x{:X}", ctx.R13),
            "r14": format!("0x{:X}", ctx.R14),
            "r15": format!("0x{:X}", ctx.R15),
            "rbp": format!("0x{:X}", ctx.Rbp),
        },
        "stackQwordsFromRsp": stack_slots,
    }))
}

unsafe fn unsafe_write_pm(h_process: HANDLE, bp_va: u64, byte: u8) -> Result<()> {
    let mut sz = 0usize;
    unsafe {
        if WriteProcessMemory(
            h_process,
            bp_va as *mut _,
            (&byte) as *const u8 as *const _,
            1,
            &mut sz,
        ) == 0
            || sz != 1
        {
            bail!("restore byte WriteProcessMemory failed at 0x{bp_va:X}");
        }
    }
    Ok(())
}

fn restore_byte_safe(h_process: HANDLE, bp_va: u64, byte: u8) -> Result<()> {
    unsafe { unsafe_write_pm(h_process, bp_va, byte) }
}

/// Point `Rip` at the restored opcode so execution is not misaligned on `ContinueDebugEvent`.
fn rewind_rip_to_breakpoint(tid: u32, bp_va: u64) -> Result<()> {
    let h_thread = unsafe {
        OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
            0,
            tid,
        )
    };
    if h_thread.is_null() {
        bail!("OpenThread(SET_CONTEXT) failed for tid={tid}");
    }
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    let ok = unsafe { GetThreadContext(h_thread, &mut ctx as *mut _) };
    if ok == 0 {
        unsafe { CloseHandle(h_thread) };
        bail!("GetThreadContext (rewind Rip) failed for tid={tid}");
    }
    ctx.Rip = bp_va;
    let ok2 = unsafe { SetThreadContext(h_thread, &ctx as *const _) };
    unsafe { CloseHandle(h_thread) };
    if ok2 == 0 {
        bail!("SetThreadContext (Rip=0x{bp_va:X}) failed for tid={tid}");
    }
    Ok(())
}

fn load_instruction(
    inline: &Option<String>,
    file_path: Option<&Path>,
) -> Result<Option<String>> {
    if let Some(p) = file_path {
        let s = fs::read_to_string(p)
            .with_context(|| format!("Failed to read --instruction-file {}", p.display()))?;
        let t = s.trim();
        if t.is_empty() {
            return Ok(None);
        }
        return Ok(Some(t.to_string()));
    }
    Ok(inline.clone())
}
