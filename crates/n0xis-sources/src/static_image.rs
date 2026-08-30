//! [`StaticImage`] — the unified static `--file` source: sniff the magic and
//! parse the file as a PE ([`StaticPe`](crate::StaticPe)) or an ELF
//! ([`StaticElf`](crate::StaticElf)), then present *one* type that delegates
//! every seam to whichever it is. The frontend stores a `StaticImage` so a
//! Windows PE and a Linux-native ELF flow through the exact same pipeline.

use std::path::Path;

use n0xis_contracts::{Module, Symbol, Va};

use crate::{MemorySource, ModuleProvider, SourceError, StaticElf, StaticPe, SymbolProvider};

/// A file-backed static image, PE or ELF, chosen by its magic bytes.
#[derive(Debug)]
pub enum StaticImage {
    Pe(StaticPe),
    Elf(StaticElf),
}

impl StaticImage {
    /// Load `path`, dispatching on the leading magic: `MZ` → PE, `\x7fELF` →
    /// ELF. Anything else is an explicit load error (rather than the old
    /// confusing "DOS header is malformed" from forcing every file through the
    /// PE parser).
    pub fn load(path: &Path) -> Result<Self, SourceError> {
        let magic = {
            let mut buf = [0u8; 4];
            use std::io::Read;
            let mut f = std::fs::File::open(path).map_err(|e| SourceError::Load(format!("open '{}': {e}", path.display())))?;
            // A short read just means "not one of the known magics".
            let _ = f.read(&mut buf);
            buf
        };
        match &magic {
            [0x7f, b'E', b'L', b'F'] => Ok(StaticImage::Elf(StaticElf::load(path)?)),
            [b'M', b'Z', ..] => Ok(StaticImage::Pe(StaticPe::load(path)?)),
            _ => Err(SourceError::Load(format!("'{}': not a PE (MZ) or ELF (\\x7fELF) image", path.display()))),
        }
    }

    pub fn image_base(&self) -> Va {
        match self {
            StaticImage::Pe(p) => p.image_base(),
            StaticImage::Elf(e) => e.image_base(),
        }
    }

    pub fn module(&self) -> &Module {
        match self {
            StaticImage::Pe(p) => p.module(),
            StaticImage::Elf(e) => e.module(),
        }
    }

    pub fn text_range(&self) -> Option<(Va, u64)> {
        match self {
            StaticImage::Pe(p) => p.text_range(),
            StaticImage::Elf(e) => e.text_range(),
        }
    }

    pub fn section_range(&self, name: &str) -> Option<(Va, u64)> {
        match self {
            StaticImage::Pe(p) => p.section_range(name),
            StaticImage::Elf(e) => e.section_range(name),
        }
    }

    /// 64-bit image? PE32+ / 64-bit ELF → `true`; 32-bit PE32 → `false`. (Only
    /// 64-bit ELF is supported, so an ELF is always 64-bit here.)
    pub fn is_64(&self) -> bool {
        match self {
            StaticImage::Pe(p) => p.is_64(),
            StaticImage::Elf(_) => true,
        }
    }

    /// Native pointer size in bytes (4 for a 32-bit PE32, else 8).
    pub fn pointer_size(&self) -> u8 {
        match self {
            StaticImage::Pe(p) => p.pointer_size(),
            StaticImage::Elf(_) => 8,
        }
    }
}

impl MemorySource for StaticImage {
    fn read(&self, va: Va, len: usize) -> Result<Vec<u8>, SourceError> {
        match self {
            StaticImage::Pe(p) => p.read(va, len),
            StaticImage::Elf(e) => e.read(va, len),
        }
    }
    fn contains(&self, va: Va) -> bool {
        match self {
            StaticImage::Pe(p) => p.contains(va),
            StaticImage::Elf(e) => e.contains(va),
        }
    }
    fn code_range(&self) -> Option<(Va, u64)> {
        match self {
            StaticImage::Pe(p) => p.code_range(),
            StaticImage::Elf(e) => e.code_range(),
        }
    }
    fn code_ranges(&self) -> Vec<(Va, u64)> {
        match self {
            StaticImage::Pe(p) => p.code_ranges(),
            StaticImage::Elf(e) => e.code_ranges(),
        }
    }
    fn label(&self) -> String {
        match self {
            StaticImage::Pe(p) => p.label(),
            StaticImage::Elf(e) => e.label(),
        }
    }
    fn abi_name(&self) -> &'static str {
        match self {
            StaticImage::Pe(p) => p.abi_name(),
            StaticImage::Elf(e) => e.abi_name(),
        }
    }
}

impl SymbolProvider for StaticImage {
    fn symbol_at(&self, va: Va) -> Option<Symbol> {
        match self {
            StaticImage::Pe(p) => p.symbol_at(va),
            StaticImage::Elf(e) => e.symbol_at(va),
        }
    }
    fn iat_slot(&self, va: Va) -> Option<Symbol> {
        match self {
            StaticImage::Pe(p) => p.iat_slot(va),
            StaticImage::Elf(e) => e.iat_slot(va),
        }
    }
}

impl ModuleProvider for StaticImage {
    fn modules(&self) -> &[Module] {
        match self {
            StaticImage::Pe(p) => p.modules(),
            StaticImage::Elf(e) => e.modules(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("n0xis_static_image_{}_{}.bin", std::process::id(), tag));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn unknown_magic_is_rejected_with_a_clear_error() {
        let p = temp("junk", b"junkjunk");
        let err = StaticImage::load(&p).unwrap_err();
        assert!(format!("{err}").contains("not a PE"), "{err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn elf_magic_routes_to_the_elf_parser_not_the_pe_parser() {
        // A truncated ELF must fail *in the ELF parser*, not with the old
        // confusing PE "DOS header is malformed" — proving the dispatch.
        let p = temp("elf", b"\x7fELFtruncated-not-a-real-elf");
        let err = StaticImage::load(&p).unwrap_err();
        let m = format!("{err}");
        assert!(!m.contains("DOS"), "ELF magic should route to the ELF parser: {m}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn mz_magic_routes_to_the_pe_parser() {
        let p = temp("pe", b"MZ-truncated-not-a-real-pe");
        let err = StaticImage::load(&p).unwrap_err();
        // It reached the PE parser (a PE-specific complaint), not the generic
        // "not a PE or ELF" rejection.
        assert!(!format!("{err}").contains("not a PE"), "MZ magic should route to the PE parser: {err}");
        let _ = std::fs::remove_file(&p);
    }
}
