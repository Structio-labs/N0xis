//! [`StringXrefPass`] — find a string literal and who references it (`xref
//! string`).
//!
//! Two independent windows, because they're usually different sections: a
//! **data** window is searched for the byte needle, a **code** window is
//! decoded once and filtered for `lea`-style RIP-relative references (via the
//! same [`DecodedInsn::rip_target`](n0xis_arch::DecodedInsn) field
//! [`XrefPass`](crate::XrefPass) already uses) that land on a match. Only
//! matches with at least one referencing instruction are reported — an
//! unreferenced byte sequence that happens to match is noise, not a "string".

use n0xis_contracts::Va;
use serde::Serialize;

use crate::xref::XrefEntry;
use crate::{Ctx, CoreError, Pass};

/// What to search for and where.
#[derive(Clone, Debug)]
pub struct StringXrefInput {
    /// Window searched for `query` (typically `.rdata`).
    pub data_start: Va,
    pub data_size: usize,
    /// Window decoded and scanned for referencing instructions (typically `.text`).
    pub code_start: Va,
    pub code_size: usize,
    pub query: String,
    /// Cap on reported hits (each hit may carry several xrefs).
    pub limit: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct StringHit {
    pub address: Va,
    /// Up to 64 bytes at the match, non-printable bytes shown as `.`.
    pub preview: String,
    pub xrefs: Vec<XrefEntry>,
}

/// The string-xref artifact (`n0xis.xref.string.v1`).
#[derive(Clone, Debug, Serialize)]
pub struct StringXrefArtifact {
    pub query: String,
    pub count: usize,
    pub hits: Vec<StringHit>,
}

/// String cross-reference pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct StringXrefPass;

impl Pass for StringXrefPass {
    type In = StringXrefInput;
    type Out = StringXrefArtifact;

    fn name(&self) -> &'static str {
        "xref.string"
    }

    fn run(&self, ctx: &Ctx, input: StringXrefInput) -> Result<StringXrefArtifact, CoreError> {
        let needle = input.query.as_bytes();
        if needle.is_empty() {
            return Ok(StringXrefArtifact { query: input.query, count: 0, hits: Vec::new() });
        }

        let data = ctx.source.read(input.data_start, input.data_size)?;
        let code_bytes = ctx.source.read(input.code_start, input.code_size)?;
        // Generous cap: a full code window can be large.
        let insns = ctx
            .arch
            .decode_stream(&code_bytes, input.code_start, code_bytes.len());

        let mut hits = Vec::new();
        let mut pos = 0usize;
        while hits.len() < input.limit {
            let Some(rel) = data[pos..].windows(needle.len()).position(|w| w == needle) else {
                break;
            };
            let idx = pos + rel;
            let str_addr = Va(input.data_start.0 + idx as u64);
            let xrefs: Vec<XrefEntry> = insns
                .iter()
                .filter(|ins| ins.rip_target == Some(str_addr))
                .map(|ins| XrefEntry {
                    from: ins.va,
                    to: str_addr,
                    kind: "data".into(),
                    text: ins.text.clone(),
                })
                .collect();
            if !xrefs.is_empty() {
                let end = (idx + 64).min(data.len());
                hits.push(StringHit {
                    address: str_addr,
                    preview: preview_ascii(&data[idx..end]),
                    xrefs,
                });
            }
            pos = idx + 1;
        }

        Ok(StringXrefArtifact { query: input.query, count: hits.len(), hits })
    }
}

/// Printable-ASCII preview; non-printable bytes render as `.`.
fn preview_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_contracts::Va;
    use n0xis_sources::Snapshot;

    #[test]
    fn finds_a_string_referenced_by_lea() {
        // Data: "Hello, world!\0" at 0x2000.
        // Code at 0x1000: lea rcx, [rip+disp] -> 0x2000 ; call somewhere ; ret
        let mut data = b"Hello, world!".to_vec();
        data.push(0);
        // lea rcx, [rip+0x0ff6]  (48 8D 0D d0 0f 00 00) chosen so rip(after insn)+disp = 0x2000
        // next_ip = 0x1007; disp = 0x2000 - 0x1007 = 0xFF9
        let disp: i32 = 0x2000 - 0x1007;
        let mut code = vec![0x48, 0x8D, 0x0D];
        code.extend_from_slice(&disp.to_le_bytes());
        code.push(0xC3); // ret

        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .region(Va(0x2000), data)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = StringXrefPass
            .run(
                &ctx,
                StringXrefInput {
                    data_start: Va(0x2000),
                    data_size: 64,
                    code_start: Va(0x1000),
                    code_size: 64,
                    query: "Hello, world!".into(),
                    limit: 10,
                },
            )
            .expect("string xref runs");

        assert_eq!(art.count, 1);
        let hit = &art.hits[0];
        assert_eq!(hit.address, Va(0x2000));
        assert!(hit.preview.starts_with("Hello, world!"));
        assert_eq!(hit.xrefs.len(), 1);
        assert_eq!(hit.xrefs[0].from, Va(0x1000));
        assert_eq!(hit.xrefs[0].kind, "data");
    }

    #[test]
    fn unreferenced_match_is_not_reported() {
        // The string exists in data but nothing in the code window points to it.
        let data = b"orphan-string\0".to_vec();
        let code = vec![0x90, 0xC3]; // nop; ret — no lea
        let snap = Snapshot::builder()
            .region(Va(0x1000), code)
            .region(Va(0x2000), data)
            .build();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);

        let art = StringXrefPass
            .run(
                &ctx,
                StringXrefInput {
                    data_start: Va(0x2000),
                    data_size: 64,
                    code_start: Va(0x1000),
                    code_size: 64,
                    query: "orphan-string".into(),
                    limit: 10,
                },
            )
            .expect("string xref runs");
        assert_eq!(art.count, 0);
    }
}
