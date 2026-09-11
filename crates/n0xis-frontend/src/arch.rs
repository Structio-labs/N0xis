// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! ISA selection — the frontend half of the `Arch` seam.

use n0xis_arch::{Arch, Arm32, Arm64, X64};

/// The ISA used when a frontend names none.
pub const DEFAULT_ARCH: &str = "x64";

/// Resolve an `--arch`/`arch` argument (default [`DEFAULT_ARCH`]) into a
/// concrete [`Arch`] (ROADMAP Phase 7: multi-arch via the ISA seam).
/// `n0xis-core` never learns which one was picked — it only ever runs against
/// `&dyn Arch`.
///
/// Every frontend should route through this rather than naming `X64::new()`
/// inline: a hardcoded ISA is an ABI fact baked into logic, which CONCEPT §3
/// rule 4 forbids, and it is why the MCP frontend was x64-only while the CLI
/// had an `--arch` flag.
pub fn resolve_arch(name: Option<&str>) -> Result<Box<dyn Arch>, String> {
    match name.unwrap_or(DEFAULT_ARCH).to_ascii_lowercase().as_str() {
        "x64" | "x86-64" | "x86_64" => Ok(Box::new(X64::new())),
        "x86" | "i386" | "x86-32" | "x86_32" => Ok(Box::new(X64::x86())),
        "arm64" | "aarch64" => Ok(Box::new(Arm64::new())),
        "arm32" | "armv7" | "aarch32" | "arm" => Ok(Box::new(Arm32::a32())),
        "thumb" | "thumb2" | "t32" => Ok(Box::new(Arm32::thumb())),
        other => Err(format!("unknown arch '{other}', expected x64|x86|arm64|arm32|thumb")),
    }
}

/// Pick the arch for a resolved source: an explicit `--arch` always wins;
/// otherwise **the image's own header decides**, and only a target that
/// declares nothing falls back to the default.
///
/// The bitness rule came first and was right as far as it went — it is what
/// keeps a PE32 from being read as x86-64 — but it only ever asked "32 or 64",
/// so an AArch64 ELF, whose header says `EM_AARCH64` and which `profile`
/// reports as `arm64`, was still disassembled as x86-64 by every analysis
/// command. The output was not empty or an error: it was four-byte ARM
/// instructions rendered as `jnp`, `sar edi,1`, `div dword ptr [rdx+53h]`,
/// with function extents to match. An instruction set is a fact the file
/// states; it is not a flag the user must remember to pass.
pub fn pick_arch_for(
    explicit: Option<&str>,
    declared_machine: Option<&str>,
    source_is_32bit: bool,
) -> Result<Box<dyn Arch>, String> {
    if let Some(a) = explicit {
        return resolve_arch(Some(a));
    }
    // A machine this build does not map (raw hex, "unknown") is not a licence
    // to guess: fall through to the bitness rule rather than decode blind.
    if let Some(m) = declared_machine
        && let Ok(a) = resolve_arch(Some(m))
    {
        return Ok(a);
    }
    if source_is_32bit {
        return Ok(Box::new(X64::x86()));
    }
    resolve_arch(None)
}

/// [`pick_arch_for`] for a caller that has no machine declaration to offer.
pub fn pick_arch(explicit: Option<&str>, source_is_32bit: bool) -> Result<Box<dyn Arch>, String> {
    pick_arch_for(explicit, None, source_is_32bit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_aliases_resolve() {
        assert_eq!(resolve_arch(None).unwrap().name(), X64::new().name());
        assert_eq!(resolve_arch(Some("x86_64")).unwrap().name(), X64::new().name());
        assert_eq!(resolve_arch(Some("AArch64")).unwrap().name(), Arm64::new().name());
    }

    #[test]
    fn unknown_arch_is_an_error_not_a_silent_default() {
        assert!(resolve_arch(Some("mips")).is_err());
    }

    /// The image's own header decides when the caller names no arch.
    #[test]
    fn a_declared_machine_beats_the_default() {
        // The defect this closes: an AArch64 ELF decoded as x86-64.
        assert_eq!(pick_arch_for(None, Some("arm64"), false).unwrap().name(), "arm64");
        assert_eq!(pick_arch_for(None, Some("x64"), false).unwrap().decoder_id(), "x86-64");
        // A 32-bit PE keeps saying so through its machine field.
        assert_eq!(pick_arch_for(None, Some("x86"), true).unwrap().decoder_id(), "x86-32");
        // An explicit flag still wins outright.
        assert_eq!(pick_arch_for(Some("x64"), Some("arm64"), false).unwrap().name(), "x86-64");
        // A machine this build cannot map falls back to the bitness rule
        // rather than decoding blind.
        assert_eq!(pick_arch_for(None, Some("0xf3"), true).unwrap().decoder_id(), "x86-32");
        assert_eq!(pick_arch_for(None, Some("unknown"), false).unwrap().decoder_id(), "x86-64");
        // No declaration at all (a live process) behaves exactly as before.
        assert_eq!(pick_arch_for(None, None, true).unwrap().decoder_id(), "x86-32");
    }
}
