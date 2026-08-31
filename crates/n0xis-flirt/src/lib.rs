//! `n0xis-flirt` — a clean-room library-function **signature matcher** in the
//! spirit of another tool's FLIRT and another tool's FunctionID: fingerprint the bytes of an
//! unnamed function and recover its real name (`free`, `memcpy`,
//! `std::_Throw_C_error`, …) from a pattern database.
//!
//! Release builds statically link a large fraction of *known* code — the CRT,
//! the STL, the runtime — which a decompiler otherwise renders `sub_XXXX` by
//! hand. Matching those bytes against a signature library names them for free,
//! the single change that most shrinks what a human must read.
//!
//! # Design
//!
//! - **Pattern + mask.** A signature is a byte pattern where the bytes that vary
//!   between builds (relocations, absolute addresses, some immediates) are
//!   **wildcards**. A function matches when its leading bytes equal the pattern
//!   on every fixed position.
//! - **Sound over complete** (the N0xis rule): when two signatures of the same
//!   specificity match with *different* names, the match is **ambiguous** and
//!   returns `None` — a decompiler must never show a *wrong* name. A longer
//!   (more specific) pattern beats a shorter one; a genuine tie is refused.
//! - **Dependency-free and format-agnostic.** The engine is a pure primitive;
//!   populating the database (from another tool FunctionID, MSVC static-CRT `.lib`s,
//!   another tool `.pat`/`.sig`, or bytes learned from a symbolized build) is a separate
//!   concern layered on top.
//!
//! ```
//! use n0xis_flirt::Db;
//! let mut db = Db::new();
//! // `..` marks a wildcard byte (e.g. a relocation the linker fills in).
//! db.add_pat("48 89 5c 24 .. 57 48 83 ec 20", "example_fn").unwrap();
//! assert_eq!(db.lookup(&[0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,0x90]), Some("example_fn"));
//! assert_eq!(db.lookup(&[0x90,0x90]), None); // no match
//! ```

use std::collections::HashMap;

/// One position in a [`Pattern`]: a fixed byte, or a wildcard that matches any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PatByte {
    Fixed(u8),
    Any,
}

/// A byte pattern with per-position wildcards — the fingerprint of a function's
/// leading bytes, tolerant of the positions a linker/compiler may vary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern(Vec<PatByte>);

impl Pattern {
    /// Parse a pattern from hex text: two hex digits per byte, `..` (or `??`)
    /// for a wildcard, whitespace ignored (`"48 89 .. c3"`). `Err` on a
    /// malformed token.
    pub fn parse(text: &str) -> Result<Pattern, ParseError> {
        let mut out = Vec::new();
        for tok in text.split_whitespace() {
            if tok == ".." || tok == "??" {
                out.push(PatByte::Any);
            } else if tok.len() == 2 {
                let b = u8::from_str_radix(tok, 16).map_err(|_| ParseError::BadByte(tok.to_string()))?;
                out.push(PatByte::Fixed(b));
            } else {
                return Err(ParseError::BadByte(tok.to_string()));
            }
        }
        if out.is_empty() {
            return Err(ParseError::Empty);
        }
        Ok(Pattern(out))
    }

    /// Number of byte positions the pattern covers.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Fixed (non-wildcard) positions — the pattern's *specificity*. A tie in
    /// length is broken by this so a pattern with more concrete bytes wins.
    pub fn fixed_count(&self) -> usize {
        self.0.iter().filter(|b| matches!(b, PatByte::Fixed(_))).count()
    }

    /// The first fixed byte, used to index the database. `None` for a pattern
    /// that begins with a wildcard (rare; those aren't indexed).
    fn first_fixed(&self) -> Option<u8> {
        self.0.first().and_then(|b| match b {
            PatByte::Fixed(v) => Some(*v),
            PatByte::Any => None,
        })
    }

    /// Does `code` begin with this pattern (every fixed position equal)?
    fn matches(&self, code: &[u8]) -> bool {
        if code.len() < self.0.len() {
            return false;
        }
        self.0.iter().zip(code).all(|(p, &c)| match p {
            PatByte::Fixed(v) => *v == c,
            PatByte::Any => true,
        })
    }

    /// Build a pattern from a function's leading bytes, wildcarding the byte
    /// ranges a linker may vary (relocated displacements: a relative call/jump
    /// target, a RIP-relative displacement). Each `(offset, len)` in `wildcards`
    /// is a half-open byte range within `window` to mask; the rest are fixed.
    ///
    /// Trailing wildcards are trimmed — a pattern ending in `..` gains no
    /// specificity yet forces the candidate to carry those bytes, so a signature
    /// must end on a concrete byte. The producer is responsible for supplying a
    /// window that ends at a real instruction boundary.
    pub fn from_window(window: &[u8], wildcards: &[(usize, usize)]) -> Pattern {
        let mut bytes: Vec<PatByte> = window.iter().map(|&b| PatByte::Fixed(b)).collect();
        for &(off, len) in wildcards {
            for pos in off..off.saturating_add(len).min(bytes.len()) {
                bytes[pos] = PatByte::Any;
            }
        }
        while matches!(bytes.last(), Some(PatByte::Any)) {
            bytes.pop();
        }
        Pattern(bytes)
    }

    /// Render as an `.npat` pattern token string: two hex digits per fixed byte,
    /// `..` per wildcard, space-separated. Round-trips through [`Pattern::parse`].
    pub fn to_npat(&self) -> String {
        self.0
            .iter()
            .map(|b| match b {
                PatByte::Fixed(v) => format!("{v:02x}"),
                PatByte::Any => "..".to_string(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// One named signature.
#[derive(Clone, Debug)]
pub struct Signature {
    pub pattern: Pattern,
    pub name: String,
}

/// A signature database, indexed by leading byte for fast lookup.
#[derive(Debug, Default)]
pub struct Db {
    sigs: Vec<Signature>,
    /// first fixed byte → indices into `sigs`.
    by_first: HashMap<u8, Vec<usize>>,
    /// signatures whose pattern starts with a wildcard — checked for every
    /// lookup (rare, so kept separate rather than bloating every bucket).
    wild_first: Vec<usize>,
}

impl Db {
    pub fn new() -> Self {
        Db::default()
    }

    /// Number of signatures loaded.
    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    /// Add a signature from a hex pattern (`..`/`??` = wildcard) and a name.
    pub fn add_pat(&mut self, pattern: &str, name: &str) -> Result<(), ParseError> {
        self.add(Signature { pattern: Pattern::parse(pattern)?, name: name.to_string() });
        Ok(())
    }

    /// Add a parsed signature.
    pub fn add(&mut self, sig: Signature) {
        let idx = self.sigs.len();
        match sig.pattern.first_fixed() {
            Some(b) => self.by_first.entry(b).or_default().push(idx),
            None => self.wild_first.push(idx),
        }
        self.sigs.push(sig);
    }

    /// The name of the function whose bytes begin `code`, or `None` when nothing
    /// matches **or the match is ambiguous** (two equally-specific signatures
    /// disagree — never guess a name). The most specific match (longest pattern,
    /// then most fixed bytes) wins outright over less specific ones.
    pub fn lookup(&self, code: &[u8]) -> Option<&str> {
        let first = code.first().copied();
        let candidates = first
            .and_then(|b| self.by_first.get(&b))
            .into_iter()
            .flatten()
            .chain(self.wild_first.iter())
            .filter(|&&i| self.sigs[i].pattern.matches(code));

        // Keep the single most-specific match; detect a same-specificity tie
        // with a different name (ambiguous → refuse).
        let mut best: Option<(&Signature, usize, usize)> = None; // (sig, len, fixed)
        let mut ambiguous = false;
        for &i in candidates {
            let s = &self.sigs[i];
            let (len, fixed) = (s.pattern.len(), s.pattern.fixed_count());
            match best {
                None => best = Some((s, len, fixed)),
                Some((bs, blen, bfixed)) => {
                    if (len, fixed) > (blen, bfixed) {
                        best = Some((s, len, fixed));
                        ambiguous = false;
                    } else if (len, fixed) == (blen, bfixed) && s.name != bs.name {
                        ambiguous = true;
                    }
                }
            }
        }
        match best {
            Some((s, _, _)) if !ambiguous => Some(&s.name),
            _ => None,
        }
    }

    /// Load a `.npat` text database: one `# comment` or `<hex-pattern> <name>`
    /// per line (the name is the last whitespace token; the pattern is
    /// everything before it). Blank lines and comments are skipped.
    pub fn load_npat(text: &str) -> Result<Db, ParseError> {
        let mut db = Db::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (pat, name) = line.rsplit_once(char::is_whitespace).ok_or(ParseError::NoName(lineno + 1))?;
            db.add_pat(pat.trim(), name.trim())?;
        }
        Ok(db)
    }
}

/// A signature-text parse failure.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// A token that is neither two hex digits nor a wildcard.
    BadByte(String),
    /// An empty pattern.
    Empty,
    /// A `.npat` line with no name token (1-indexed).
    NoName(usize),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::BadByte(t) => write!(f, "bad pattern byte {t:?}"),
            ParseError::Empty => write!(f, "empty pattern"),
            ParseError::NoName(n) => write!(f, "line {n}: signature has no name"),
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixed_and_wildcard_bytes() {
        let p = Pattern::parse("48 89 .. c3").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.fixed_count(), 3);
        assert!(p.matches(&[0x48, 0x89, 0xff, 0xc3, 0x90]));
        assert!(p.matches(&[0x48, 0x89, 0x00, 0xc3]));
        assert!(!p.matches(&[0x48, 0x88, 0x00, 0xc3])); // fixed byte differs
        assert!(!p.matches(&[0x48, 0x89, 0x00])); // too short
    }

    #[test]
    fn rejects_a_malformed_pattern() {
        assert_eq!(Pattern::parse("48 8"), Err(ParseError::BadByte("8".into())));
        assert_eq!(Pattern::parse(""), Err(ParseError::Empty));
    }

    #[test]
    fn looks_up_a_matching_function_and_misses_a_non_match() {
        let mut db = Db::new();
        db.add_pat("48 89 5c 24 .. 57", "free").unwrap();
        assert_eq!(db.lookup(&[0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x90]), Some("free"));
        assert_eq!(db.lookup(&[0x90]), None);
        assert_eq!(db.lookup(&[0x48, 0x89, 0x5c, 0x24, 0x08, 0x58]), None); // last byte differs
    }

    #[test]
    fn the_most_specific_signature_wins() {
        let mut db = Db::new();
        db.add_pat("48 89", "generic_prologue").unwrap();
        db.add_pat("48 89 5c 24 08", "specific_fn").unwrap();
        // The longer, more specific pattern is chosen over the short one.
        assert_eq!(db.lookup(&[0x48, 0x89, 0x5c, 0x24, 0x08, 0xc3]), Some("specific_fn"));
    }

    #[test]
    fn an_ambiguous_match_refuses_to_guess() {
        // Two equally-specific signatures disagree on the name → None, never a
        // wrong guess (sound over complete).
        let mut db = Db::new();
        db.add_pat("48 89 c3", "alpha").unwrap();
        db.add_pat("48 89 c3", "beta").unwrap();
        assert_eq!(db.lookup(&[0x48, 0x89, 0xc3, 0x90]), None);
        // But a same-name duplicate is not ambiguous.
        let mut db2 = Db::new();
        db2.add_pat("48 89 c3", "same").unwrap();
        db2.add_pat("48 89 c3", "same").unwrap();
        assert_eq!(db2.lookup(&[0x48, 0x89, 0xc3]), Some("same"));
    }

    #[test]
    fn loads_an_npat_text_database() {
        let text = "# CRT signatures\n48 89 5c 24 .. 57   free\n48 83 ec 28   memcpy\n\n";
        let db = Db::load_npat(text).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.lookup(&[0x48, 0x89, 0x5c, 0x24, 0x08, 0x57]), Some("free"));
        assert_eq!(db.lookup(&[0x48, 0x83, 0xec, 0x28, 0x90]), Some("memcpy"));
    }

    #[test]
    fn builds_a_pattern_and_round_trips_through_npat() {
        // `e8 <rel32> 90` — a relative call whose 4 displacement bytes vary
        // between builds, so they must become wildcards.
        let window = [0xe8, 0x11, 0x22, 0x33, 0x44, 0x90];
        let pat = Pattern::from_window(&window, &[(1, 4)]);
        assert_eq!(pat.to_npat(), "e8 .. .. .. .. 90");
        // A pattern round-trips: format then parse yields the same thing.
        assert_eq!(Pattern::parse(&pat.to_npat()).unwrap(), pat);
        // It matches a differently-relocated instance of the same code…
        assert!(pat.matches(&[0xe8, 0xaa, 0xbb, 0xcc, 0xdd, 0x90]));
        // …but not code that differs on a fixed byte.
        assert!(!pat.matches(&[0xe8, 0xaa, 0xbb, 0xcc, 0xdd, 0x91]));
    }

    #[test]
    fn trailing_wildcards_are_trimmed() {
        // A window ending in a relocated tail must not keep dangling `..`: they
        // add no specificity yet would force the candidate to carry those bytes.
        let window = [0x48, 0x83, 0xec, 0x28, 0xe9, 0x11, 0x22, 0x33, 0x44];
        let pat = Pattern::from_window(&window, &[(5, 4)]);
        assert_eq!(pat.to_npat(), "48 83 ec 28 e9");
    }
}
