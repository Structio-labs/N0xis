// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What this host gives one run, for the engine's memory ceiling: the OS side of
//! `n0xis_core::set_memory_ceiling`.

/// The most of the machine's memory one run takes by default.
fn share_of_ram(bytes: u64) -> u64 {
    bytes / 4 * 3
}

/// The ceiling for a cgroup's limit. The limit counts what the kernel charges, the
/// ceiling what the allocator handed out: a quarter is left for the page cache,
/// thread stacks and the heap's own fragmentation, so the engine stops first.
fn share_of_cgroup(bytes: u64) -> u64 {
    bytes / 4 * 3
}

/// The ceiling for this run, from what `stated` asks (`N0X_MEMORY_MAX`) and what the
/// host gives. A stated size replaces the share of the machine and can never pass
/// a cgroup's limit, because the kernel would hold the run to that anyway.
fn ceiling_from(stated: Option<u64>, ram: Option<u64>, cgroup: Option<u64>) -> Option<u64> {
    let own = stated.or(ram.map(share_of_ram));
    match (own, cgroup.map(share_of_cgroup)) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The memory ceiling for this run, or `None` where nothing states one.
pub fn memory_ceiling(stated: Option<u64>) -> Option<u64> {
    ceiling_from(stated, physical_memory(), cgroup_limit())
}

#[cfg(target_os = "linux")]
fn physical_memory() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    line.split_whitespace().nth(1)?.parse::<u64>().ok()?.checked_mul(1024)
}

/// The tightest `memory.max` on the way up this process's cgroup.
#[cfg(target_os = "linux")]
fn cgroup_limit() -> Option<u64> {
    let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = own.lines().find_map(|l| l.strip_prefix("0::"))?;
    let mut dir = std::path::PathBuf::from(format!("/sys/fs/cgroup{path}"));
    let mut tightest = None;
    loop {
        if let Ok(text) = std::fs::read_to_string(dir.join("memory.max"))
            && let Ok(limit) = text.trim().parse::<u64>()
        {
            tightest = Some(tightest.map_or(limit, |t: u64| t.min(limit)));
        }
        if !dir.pop() || !dir.starts_with("/sys/fs/cgroup") {
            return tightest;
        }
    }
}

#[cfg(all(windows, feature = "live"))]
fn physical_memory() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: the structure is plain data, zero is valid for every field, and its
    // length is set as the call requires.
    unsafe {
        let mut status: MEMORYSTATUSEX = std::mem::zeroed();
        status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
        (GlobalMemoryStatusEx(&mut status) != 0).then_some(status.ullTotalPhys)
    }
}

#[cfg(not(any(target_os = "linux", all(windows, feature = "live"))))]
fn physical_memory() -> Option<u64> {
    None
}

#[cfg(not(target_os = "linux"))]
fn cgroup_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: u64 = 1 << 30;

    #[test]
    fn the_tightest_of_what_is_stated_and_what_the_host_gives() {
        assert_eq!(ceiling_from(None, Some(16 * G), None), Some(12 * G), "three quarters of the machine");
        assert_eq!(ceiling_from(None, Some(16 * G), Some(6 * G)), Some(6 * G / 4 * 3), "a cgroup below that");
        assert_eq!(ceiling_from(Some(2 * G), Some(16 * G), Some(6 * G)), Some(2 * G), "asked for less");
        assert_eq!(ceiling_from(Some(32 * G), Some(16 * G), None), Some(32 * G), "the machine's share can be overridden");
        assert_eq!(ceiling_from(Some(32 * G), Some(16 * G), Some(6 * G)), Some(6 * G / 4 * 3), "a cgroup cannot");
        assert_eq!(ceiling_from(None, None, None), None, "nothing stated, nothing invented");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_host_states_something() {
        let ram = physical_memory().expect("/proc/meminfo");
        let ceiling = memory_ceiling(None).expect("a ceiling");
        assert!(ceiling > 0 && ceiling <= ram, "{ceiling} of {ram}");
    }
}
