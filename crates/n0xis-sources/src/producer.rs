// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! What an image shows of the compiler that built it, read from the image and
//! nothing else. Today one question: whether rustc did.

use serde::Serialize;

use crate::Image;

/// What in an image shows that rustc built at least part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RustcEvidence {
    /// rustc naming itself in `.comment`.
    RustcComment,
    /// A `/rustc/<40 hex>/` path in its text: where a panic location in the
    /// standard library says it was compiled, which stripping leaves.
    RustcPath,
}

/// What rustc writes of itself in `.comment`, alone (`rustc version 1.99.0 (...)`)
/// or inside another tool's entry (`clang LLVM (rustc version 1.60.0 ...)`). The
/// word alone is not enough: this section is free text.
const COMMENT: &[u8] = b"rustc version ";

const PATH: &[u8] = b"/rustc/";
const PATH_HASH_LEN: usize = 40;

/// What shows that rustc built at least part of `image`, the section where it
/// names itself first since it costs nothing to read; `None` when nothing does.
/// Mixed images count: a C library linked into a Rust program, and the reverse.
///
/// Sections that hold code are not text. A range the file does not hold reads as
/// nothing rather than failing: no evidence is the answer that changes nothing.
pub fn rustc_evidence(image: &dyn Image) -> Option<RustcEvidence> {
    if image.comment().is_some_and(|comment| comment.windows(COMMENT.len()).any(|w| w == COMMENT)) {
        return Some(RustcEvidence::RustcComment);
    }
    let file = image.loaded_bytes().file;
    let in_file = |offset: u64, size: u64| file.get(usize::try_from(offset).ok()?..usize::try_from(offset.checked_add(size)?).ok()?);
    let mut text = image.sections().iter().filter(|s| !s.executable && s.file_size > 0).filter_map(|s| in_file(s.file_offset, s.file_size));
    text.any(holds_rustc_path).then_some(RustcEvidence::RustcPath)
}

/// Whether `bytes` hold `/rustc/`, 40 lowercase hex digits and a `/`: a word that
/// happens to say `rustc` is not this, and neither is a path a build was asked to
/// write in another form.
fn holds_rustc_path(bytes: &[u8]) -> bool {
    bytes.windows(PATH.len()).enumerate().filter(|(_, w)| *w == PATH).any(|(at, _)| {
        let rest = &bytes[at + PATH.len()..];
        rest.get(PATH_HASH_LEN) == Some(&b'/') && rest[..PATH_HASH_LEN].iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4";

    #[test]
    fn a_path_is_the_whole_shape_and_nothing_less() {
        assert!(holds_rustc_path(format!("x\0/rustc/{HASH}/library/core/src/str/mod.rs\0").as_bytes()));
        assert!(holds_rustc_path(format!("/rustc/{HASH}/").as_bytes()));
        assert!(!holds_rustc_path(b"built with rustc 1.99"));
        assert!(!holds_rustc_path(b"/usr/lib/rustc/"));
        // Too short, too long, not hex, not lowercase, no slash after.
        assert!(!holds_rustc_path(format!("/rustc/{}/", &HASH[1..]).as_bytes()));
        assert!(!holds_rustc_path(format!("/rustc/{HASH}0/").as_bytes()));
        assert!(!holds_rustc_path(format!("/rustc/{}g/", &HASH[1..]).as_bytes()));
        assert!(!holds_rustc_path(format!("/rustc/{}/", HASH.to_uppercase()).as_bytes()));
        assert!(!holds_rustc_path(format!("/rustc/{HASH}").as_bytes()));
        assert!(!holds_rustc_path(format!("/rustc/{HASH} ").as_bytes()));
    }

    #[test]
    fn a_false_start_does_not_hide_the_path_after_it() {
        assert!(holds_rustc_path(format!("/rustc//rustc/{HASH}/").as_bytes()));
    }
}
