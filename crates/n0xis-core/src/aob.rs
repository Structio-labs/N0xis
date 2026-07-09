//! AOB (array-of-bytes) signature scanning with wildcards (ROADMAP Phase 4b)
//! — used for code-cave/anchor discovery and version-resilient hooking (an
//! AOB signature survives a patch/recompile that a raw address wouldn't).

use n0xis_contracts::Va;
use serde::Serialize;

use crate::{Ctx, CoreError, Pass};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AobByte {
    Exact(u8),
    Wildcard,
}

/// Parse a a memory scanner-style pattern (`"48 8B ?? 68"`, `?` or `??` as a
/// wildcard token) into a byte-matchable pattern.
pub fn parse_aob(pattern: &str) -> Result<Vec<AobByte>, String> {
    pattern
        .split_whitespace()
        .map(|tok| match tok {
            "?" | "??" => Ok(AobByte::Wildcard),
            _ => u8::from_str_radix(tok, 16).map(AobByte::Exact).map_err(|_| format!("invalid AOB byte token: {tok:?}")),
        })
        .collect()
}

pub struct AobInput {
    pub start: Va,
    pub size: usize,
    pub pattern: Vec<AobByte>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AobArtifact {
    pub matches: Vec<Va>,
    pub bytes_scanned: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AobScanPass;

impl Pass for AobScanPass {
    type In = AobInput;
    type Out = AobArtifact;

    fn name(&self) -> &'static str {
        "scan.aob"
    }

    fn run(&self, ctx: &Ctx, input: AobInput) -> Result<AobArtifact, CoreError> {
        let bytes = ctx.source.read(input.start, input.size)?;
        let plen = input.pattern.len();
        let mut matches = Vec::new();
        if plen == 0 || bytes.len() < plen {
            return Ok(AobArtifact { matches, bytes_scanned: bytes.len() });
        }
        for i in 0..=(bytes.len() - plen) {
            let hit = input.pattern.iter().enumerate().all(|(k, p)| match p {
                AobByte::Wildcard => true,
                AobByte::Exact(b) => bytes[i + k] == *b,
            });
            if hit {
                matches.push(input.start.offset(i as u64));
            }
        }
        Ok(AobArtifact { matches, bytes_scanned: bytes.len() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    #[test]
    fn parses_wildcards_and_hex_bytes() {
        let pattern = parse_aob("48 8B ?? 68").unwrap();
        assert_eq!(pattern, vec![AobByte::Exact(0x48), AobByte::Exact(0x8B), AobByte::Wildcard, AobByte::Exact(0x68)]);
    }

    #[test]
    fn rejects_a_malformed_token() {
        assert!(parse_aob("zz").is_err());
    }

    #[test]
    fn finds_two_matches_with_a_wildcard_byte() {
        let code = vec![0x48, 0x8B, 0x50, 0x68, 0x90, 0x48, 0x8B, 0x60, 0x68, 0xC3];
        let snap = Snapshot::builder().region(Va(0x1000), code).build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let pattern = parse_aob("48 8B ?? 68").unwrap();
        let art = AobScanPass.run(&ctx, AobInput { start: Va(0x1000), size: 10, pattern }).unwrap();
        assert_eq!(art.matches, vec![Va(0x1000), Va(0x1005)]);
    }
}
