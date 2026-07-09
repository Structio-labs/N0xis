//! Pointer-path scanning (ROADMAP Phase 4b) — find stable multi-level
//! pointer chains (`[[base+a]+b]+c`) that resolve to a target address,
//! anchored in caller-supplied "static" root regions (a module's `.data`
//! range is the natural root: its address survives an ASLR rebase as
//! `module+offset`, unlike a heap allocation).
//!
//! Built compositionally on [`crate::ScanPass`] rather than a bespoke
//! reverse-pointer index: "what points near `X`" *is* a value scan for `X`
//! (± a plausible struct-offset window) over the candidate roots. Each level
//! of the BFS is one [`ScanPass`] run against the previous level's
//! addresses — a pass composing a pass, à la LLVM/Bevy systems (CONCEPT §5.3).

use n0xis_contracts::Va;
use serde::Serialize;

use crate::scan::{ScanCriterion, ScanInput, ScanPass, ScanValue, ValueType};
use crate::{Ctx, CoreError, Pass};

/// A "static" anchor a pointer chain can be rooted in — typically a module's
/// `.data`/`.bss` range, so `root_label + root_offset` reads the same
/// logical slot across restarts even under ASLR (only the module's *base*
/// moves; the offset within it doesn't).
#[derive(Clone, Debug)]
pub struct PointerRoot {
    pub label: String,
    pub start: Va,
    pub size: u64,
}

pub struct PointerPathInput {
    pub target: Va,
    /// All regions to search for pointer *candidates* at every BFS level —
    /// typically the full memory map (heap + every module's writable
    /// sections), since the pointer chain to `target` can pass through
    /// ordinary heap allocations before it reaches a stable anchor.
    pub search_regions: Vec<(Va, usize)>,
    /// The subset of address space that counts as a stable anchor a chain
    /// can *terminate* in (e.g. a module's `.data`/`.bss`). A hit elsewhere
    /// just continues the BFS one level deeper; a hit inside a root gets
    /// recorded as a [`PointerPath`].
    pub roots: Vec<PointerRoot>,
    /// How many dereferences to search back through.
    pub max_depth: usize,
    /// Max plausible struct-field offset per hop — keeps the search from
    /// treating any coincidental pointer-sized match as a real field access.
    pub max_offset: u64,
    /// 8 on x64.
    pub pointer_size: usize,
}

/// A discovered chain: starting at `root_label + root_offset`, dereference
/// and add `offsets[i]` — **applied in reverse** (`offsets.last()` first,
/// `offsets[0]` last) — to reach `target`. See [`resolve_pointer_path`] for
/// the exact walk, and the module docs for why the order comes out reversed
/// (the search runs backward from the target).
#[derive(Clone, Debug, Serialize)]
pub struct PointerPath {
    pub root_label: String,
    pub root_offset: u64,
    pub offsets: Vec<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PointerPathArtifact {
    pub paths: Vec<PointerPath>,
    pub nodes_visited: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PointerPathPass;

impl Pass for PointerPathPass {
    type In = PointerPathInput;
    type Out = PointerPathArtifact;

    fn name(&self) -> &'static str {
        "scan.pointer_path"
    }

    fn run(&self, ctx: &Ctx, input: PointerPathInput) -> Result<PointerPathArtifact, CoreError> {
        let ptr_ty = if input.pointer_size >= 8 { ValueType::U64 } else { ValueType::U32 };
        let regions = &input.search_regions;

        let mut paths = Vec::new();
        let mut nodes_visited = 0usize;
        // Frontier: (address we're currently looking for a pointer *to*, the
        // offsets accumulated so far, target-side first).
        let mut frontier: Vec<(Va, Vec<i64>)> = vec![(input.target, Vec::new())];

        for _ in 0..input.max_depth {
            let mut next_frontier = Vec::new();
            for (pointee, path_so_far) in &frontier {
                let lo = pointee.get() as i64 - input.max_offset as i64;
                let hi = pointee.get() as i64 + input.max_offset as i64;
                let scan = ScanPass.run(
                    ctx,
                    ScanInput {
                        regions: regions.clone(),
                        value_type: ptr_ty,
                        criterion: ScanCriterion::InRange { min: ScanValue::Int(lo), max: ScanValue::Int(hi) },
                        align: input.pointer_size,
                    },
                )?;
                nodes_visited += scan.matches.len();

                for m in scan.matches {
                    let offset = pointee.get() as i64 - m.value.as_int();
                    let mut new_path = path_so_far.clone();
                    new_path.push(offset);

                    if let Some(root) = input.roots.iter().find(|r| m.addr.get() >= r.start.get() && m.addr.get() < r.start.get() + r.size) {
                        paths.push(PointerPath {
                            root_label: root.label.clone(),
                            root_offset: m.addr.get() - root.start.get(),
                            offsets: new_path.clone(),
                        });
                    }
                    next_frontier.push((m.addr, new_path));
                }
            }
            if next_frontier.is_empty() {
                break;
            }
            frontier = next_frontier;
        }

        Ok(PointerPathArtifact { paths, nodes_visited })
    }
}

/// Walk a discovered chain forward from its root to confirm/re-resolve where
/// it lands right now — the "ASLR-resilient rescan" ROADMAP asks for: call
/// again after a restart with the *new* root base and this reproduces the
/// same logical address without re-running the full search.
pub fn resolve_pointer_path(ctx: &Ctx, path: &PointerPath, roots: &[PointerRoot], pointer_size: usize) -> Option<Va> {
    let root = roots.iter().find(|r| r.label == path.root_label)?;
    let mut addr = root.start.offset(path.root_offset);
    for &off in path.offsets.iter().rev() {
        let bytes = ctx.source.read(addr, pointer_size).ok()?;
        let ptr = if pointer_size >= 8 {
            u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?)
        } else {
            u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as u64
        };
        addr = Va((ptr as i64).wrapping_add(off) as u64);
    }
    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0xis_arch::X64;
    use n0xis_sources::Snapshot;

    /// root(.data @ 0x5000) --> heap A (0x9000) --> heap B (0xA000, +0x10) == target (0xA010).
    fn build_two_hop_world() -> (Snapshot, Va) {
        let mut data = vec![0u8; 0x20];
        data[0..8].copy_from_slice(&0x9000u64.to_le_bytes()); // root+0 -> A
        let mut heap_a = vec![0u8; 0x20];
        heap_a[0x8..0x10].copy_from_slice(&0xA000u64.to_le_bytes()); // A+8 -> B
        let target = Va(0xA010);
        let snap = Snapshot::builder()
            .region(Va(0x5000), data)
            .region(Va(0x9000), heap_a)
            .region(Va(0xA000), vec![0u8; 0x20])
            .build();
        (snap, target)
    }

    #[test]
    fn finds_a_two_hop_chain_rooted_in_a_static_region() {
        let (snap, target) = build_two_hop_world();
        let arch = X64::new();
        let ctx = Ctx::new(&snap, &arch);
        let roots = vec![PointerRoot { label: "mod.data".to_string(), start: Va(0x5000), size: 0x20 }];
        let search_regions = vec![(Va(0x5000), 0x20), (Va(0x9000), 0x20), (Va(0xA000), 0x20)];

        let art = PointerPathPass
            .run(
                &ctx,
                PointerPathInput {
                    target,
                    search_regions,
                    roots: roots.clone(),
                    max_depth: 3,
                    max_offset: 0x40,
                    pointer_size: 8,
                },
            )
            .unwrap();
        assert!(!art.paths.is_empty(), "expected at least one chain");
        let path = &art.paths[0];
        assert_eq!(path.root_label, "mod.data");
        assert_eq!(path.root_offset, 0);

        let resolved = resolve_pointer_path(&ctx, path, &roots, 8).expect("resolves");
        assert_eq!(resolved, target);
    }
}
