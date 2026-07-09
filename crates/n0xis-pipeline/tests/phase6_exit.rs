//! **Phase 6 exit test (artifact caching slice)**: `cfg_cached` must (1) miss
//! and populate the cache on the first call, (2) hit and return an identical
//! artifact on a repeat call over unchanged bytes, and (3) miss again — never
//! silently reusing a stale artifact — the moment the underlying bytes at the
//! same address actually change (the self-modifying-code / hot-patch case).
//! Entirely OS-free (`Snapshot`, no live process needed): the invalidation
//! story only depends on content hashing, not on any live-source behavior.

use std::fs;

use n0xis_arch::X64;
use n0xis_core::{CfgInput, Ctx};
use n0xis_contracts::Va;
use n0xis_pipeline::cfg_cached;
use n0xis_sources::Snapshot;

// mov eax, 1 ; ret
const FN_V1: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
// mov eax, 2 ; nop ; ret  (different byte count *and* instruction count)
const FN_V2: &[u8] = &[0xB8, 0x02, 0x00, 0x00, 0x00, 0x90, 0xC3];

fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
    let tmp = std::env::temp_dir().join(format!(
        "n0xis-phase6-exit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(tmp.join(".n0x")).expect("create scratch .n0x project");
    let prev = std::env::current_dir().expect("read cwd");
    std::env::set_current_dir(&tmp).expect("cd into scratch project");
    let result = f();
    std::env::set_current_dir(prev).ok();
    fs::remove_dir_all(&tmp).ok();
    result
}

#[test]
fn cache_hits_on_unchanged_bytes_and_invalidates_on_change() {
    in_temp_project(|| {
        let arch = X64::new();
        let input = CfgInput::new(Va(0x1000), 64);

        // First call: nothing cached yet.
        let snap_v1 = Snapshot::builder().region(Va(0x1000), FN_V1.to_vec()).label("snapshot:phase6").build();
        let ctx = Ctx::new(&snap_v1, &arch);
        let (art1, cached1) = cfg_cached(&ctx, input).expect("cfg_cached (miss)");
        assert!(!cached1, "first call must be a miss");
        assert_eq!(art1.insn_count, 2, "mov+ret decodes to 2 instructions");

        // Second call, same bytes (a fresh Snapshot instance, but byte-identical):
        // must hit and return the same artifact shape.
        let snap_v1_again = Snapshot::builder().region(Va(0x1000), FN_V1.to_vec()).label("snapshot:phase6").build();
        let ctx = Ctx::new(&snap_v1_again, &arch);
        let (art2, cached2) = cfg_cached(&ctx, input).expect("cfg_cached (hit)");
        assert!(cached2, "second call over identical bytes must be a cache hit");
        assert_eq!(art2.insn_count, art1.insn_count);
        assert_eq!(art2.block_count, art1.block_count);
        assert_eq!(
            serde_json::to_string(&art2).unwrap(),
            serde_json::to_string(&art1).unwrap(),
            "a cache hit must return the identical artifact, not a re-derived approximation"
        );

        // Third call: the *same address* now holds different bytes (simulates
        // self-modifying code / a hot patch). Must miss — never hand back the
        // stale v1 artifact — and reflect the new code.
        let snap_v2 = Snapshot::builder().region(Va(0x1000), FN_V2.to_vec()).label("snapshot:phase6").build();
        let ctx = Ctx::new(&snap_v2, &arch);
        let (art3, cached3) = cfg_cached(&ctx, input).expect("cfg_cached (invalidated)");
        assert!(!cached3, "changed bytes at the same address must invalidate the cache, not reuse it");
        assert_eq!(art3.insn_count, 3, "mov+nop+ret decodes to 3 instructions");

        // And a repeat of v2 now hits its own (new) cache entry.
        let snap_v2_again = Snapshot::builder().region(Va(0x1000), FN_V2.to_vec()).label("snapshot:phase6").build();
        let ctx = Ctx::new(&snap_v2_again, &arch);
        let (_art4, cached4) = cfg_cached(&ctx, input).expect("cfg_cached (hit on v2)");
        assert!(cached4, "repeat of the new bytes must hit the newly-populated entry");
    });
}
