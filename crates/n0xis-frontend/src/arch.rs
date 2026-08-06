//! ISA selection — the frontend half of the `Arch` seam.

use n0xis_arch::{Arch, Arm64, X64};

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
        "arm64" | "aarch64" => Ok(Box::new(Arm64::new())),
        other => Err(format!("unknown arch '{other}', expected x64|arm64")),
    }
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
}
