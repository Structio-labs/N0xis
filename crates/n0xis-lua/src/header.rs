//! The dump header — `header = ESC 'L' 'J' versionB flagsU [namelenU
//! nameB*]` per `lj_bcdump.h`, read exactly as `lj_bcread.c: bcread_header`.

use crate::reader::Reader;
use crate::LuaError;

const HEAD1: u8 = 0x1b;
const HEAD2: u8 = b'L';
const HEAD3: u8 = b'J';

/// LuaJIT 2.0's dump format version. Bundled Helldivers 1 scripts (LuaJIT
/// 2.0.3) use exactly this; a different byte here means either a different
/// LuaJIT branch (2.1 added `BCDUMP_F_FR2`) or a non-LuaJIT dump, and this
/// crate reports that as an error rather than guessing at a layout it hasn't
/// verified.
pub const SUPPORTED_VERSION: u8 = 1;

const F_BE: u32 = 0x01;
const F_STRIP: u32 = 0x02;
const F_FFI: u32 = 0x04;
const F_KNOWN: u32 = F_BE | F_STRIP | F_FFI;

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    pub big_endian: bool,
    pub strip: bool,
    pub ffi: bool,
    pub chunk_name: Option<String>,
}

pub fn parse_header(r: &mut Reader) -> Result<Header, LuaError> {
    let h1 = r.byte()?;
    if h1 != HEAD1 {
        return Err(LuaError::NotLuaJit);
    }
    let h2 = r.byte()?;
    let h3 = r.byte()?;
    if h2 != HEAD2 || h3 != HEAD3 {
        return Err(LuaError::NotLuaJit);
    }
    let version = r.byte()?;
    if version != SUPPORTED_VERSION {
        return Err(LuaError::UnsupportedVersion(version));
    }
    let flags = r.uleb128()?;
    if flags & !F_KNOWN != 0 {
        return Err(LuaError::Malformed("dump header has unrecognized flag bits set"));
    }
    let strip = flags & F_STRIP != 0;
    let chunk_name = if strip {
        None
    } else {
        let len = r.uleb128()? as usize;
        Some(String::from_utf8_lossy(r.take(len)?).into_owned())
    };
    Ok(Header { version, big_endian: flags & F_BE != 0, strip, ffi: flags & F_FFI != 0, chunk_name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_stripped_header_with_no_chunk_name() {
        let bytes = [HEAD1, HEAD2, HEAD3, SUPPORTED_VERSION, F_STRIP as u8];
        let mut r = Reader::new(&bytes);
        let h = parse_header(&mut r).unwrap();
        assert!(h.strip);
        assert_eq!(h.chunk_name, None);
    }

    #[test]
    fn parses_an_unstripped_header_with_a_chunk_name() {
        let name = b"@test.lua";
        let mut bytes = vec![HEAD1, HEAD2, HEAD3, SUPPORTED_VERSION, 0x00, name.len() as u8];
        bytes.extend_from_slice(name);
        let mut r = Reader::new(&bytes);
        let h = parse_header(&mut r).unwrap();
        assert!(!h.strip);
        assert_eq!(h.chunk_name.as_deref(), Some("@test.lua"));
    }

    #[test]
    fn rejects_wrong_magic() {
        let bytes = [0x00, HEAD2, HEAD3, SUPPORTED_VERSION, 0x02];
        let mut r = Reader::new(&bytes);
        assert!(matches!(parse_header(&mut r), Err(LuaError::NotLuaJit)));
    }

    #[test]
    fn rejects_unknown_version() {
        let bytes = [HEAD1, HEAD2, HEAD3, 99, 0x02];
        let mut r = Reader::new(&bytes);
        assert!(matches!(parse_header(&mut r), Err(LuaError::UnsupportedVersion(99))));
    }

    #[test]
    fn rejects_unknown_flag_bits() {
        let bytes = [HEAD1, HEAD2, HEAD3, SUPPORTED_VERSION, 0x80, 0x01];
        let mut r = Reader::new(&bytes);
        assert!(parse_header(&mut r).is_err());
    }
}
