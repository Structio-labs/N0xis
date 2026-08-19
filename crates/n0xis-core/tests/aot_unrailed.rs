//! Live validation of the NativeAOT reader against the Unrailed 2 image.
//! Skips cleanly when the game isn't installed on this machine.

use std::path::Path;

const DLL: &str = "/run/media/tim/Games/SteamLibrary/steamapps/common/Unrailed! 2 Back on Track/data_UnrailedGodot_windows_x86_64/UnrailedGodot.dll";

#[test]
fn resolves_oracle_names_from_the_image() {
    if !Path::new(DLL).exists() {
        eprintln!("skip: DLL not present");
        return;
    }
    let pe = n0xis_sources::StaticPe::load(Path::new(DLL)).expect("load pe");
    {
        use n0xis_sources::MemorySource;
        let ib = pe.image_base().0;
        let em = pe.read(n0xis_contracts::Va(ib + 0x3883d80), 6844307).map(|v| v.len()).unwrap_or(0);
        let mp = pe.read(n0xis_contracts::Va(ib + 0x44eae60), 588561).map(|v| v.len()).unwrap_or(0);
        eprintln!("[probe] read embedded(want 6844307)={em} map(want 588561)={mp}");
    }
    let art = n0xis_core::parse_aot(&pe, pe.image_base()).expect("parse aot");

    eprintln!(
        "header_rva=0x{:x} version={} methods={} embedded=0x{:x}({}) map=0x{:x}({})",
        art.header_rva,
        art.version,
        art.method_count,
        art.embedded_metadata.rva,
        art.embedded_metadata.size,
        art.rva_to_token.rva,
        art.rva_to_token.size,
    );
    assert!(art.method_count > 100, "expected a populated map");

    if std::env::var_os("N0X_AOT_DEBUG").is_some() {
        let clip = |s: &str, n: usize| -> String { s.chars().take(n).collect() };
        let clean = art.symbols.iter().filter(|s| s.name.is_ascii()).count();
        eprintln!("[diag] returned={} clean_ascii_names={}/{}",
            art.symbols.len(), clean, art.symbols.len());
        eprintln!("[diag] sample of ASCII names:");
        for s in art.symbols.iter().filter(|s| s.name.is_ascii() && s.name.contains('.')).take(20) {
            eprintln!("  0x{:<8x} {}", s.rva, clip(&s.display, 100));
        }
        let ug = art.symbols.iter().filter(|s| s.name.contains("UnrailedGodot")).count();
        eprintln!("[diag] UnrailedGodot.* methods in map: {ug}");
        for s in art.symbols.iter().filter(|s| s.name.contains("MainGame")).take(12) {
            eprintln!("  MainGame: 0x{:<8x} {}", s.rva, clip(&s.display, 110));
        }
        eprintln!("[diag] modding-target search:");
        for needle in ["AddBot", "MaxPlayers", "Bot", "Lobby", "PlayerCount",
                       "GameStarted", "Config", "Multiplayer", "AssetLoader", "common."] {
            let hits: Vec<_> = art.symbols.iter().filter(|s| s.name.contains(needle)).collect();
            eprintln!("  '{needle}': {} hits", hits.len());
            for s in hits.iter().take(3) {
                eprintln!("       0x{:<8x} {}", s.rva, clip(&s.display, 100));
            }
        }
    }

    // Every entry resolves to a clean, fully-qualified managed name.
    assert_eq!(
        art.symbols.iter().filter(|s| s.name.is_ascii()).count(),
        art.symbols.len(),
        "some names failed to resolve to clean ASCII"
    );
    eprintln!(
        "[diag] method_count={} stacktrace={} invoke={}",
        art.method_count, art.stacktrace_count, art.invoke_count
    );
    // Stack-trace names (framework/generic) + InvokeMap names (reflection
    // surface incl. gameplay methods) — proves both sources resolve end to end.
    for needle in [
        "Godot.GodotObject.Finalize",              // stacktrace
        "common.AssetHandle..cctor",               // stacktrace
        "GameSetupMenu.GetMaxPlayersOptions",      // invoke (the modding target)
        "GameEscapeMenu.AddBot",                   // invoke
        "ControllerManager.AddBot",                // invoke
    ] {
        match art.symbols.iter().find(|s| s.name.contains(needle)) {
            Some(s) => eprintln!("  OK 0x{:<8x} [{}] {}", s.rva, s.source, s.name.chars().take(80).collect::<String>()),
            None => panic!("expected to resolve {needle}"),
        }
    }
}
