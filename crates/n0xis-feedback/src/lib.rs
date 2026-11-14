// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # n0xis-feedback: what a report is, on both sides of the wire
//!
//! `n0x feedback` builds a report and the receiver takes it apart, and both do it through this
//! crate, so the schema has one source (docs/FEEDBACK.md is the public note on what is sent). No
//! I/O here: the client's network is `n0xis-update`'s, the receiver's is its own crate.
//!
//! **A report holds nothing about what is being analysed, by its shape.** [`Report`] has a field for
//! the schema, the tool's version, the OS and architecture, the user's text, and each attachment's
//! type, size and digest, and no other: there is no place in it for a path, a file name, an address,
//! bytes of a target or anything that tells one machine from another. An attachment's own name is
//! not sent either, since a screenshot's file name is often the target's. The receiver parses with
//! `deny_unknown_fields`, so a report carrying anything else is refused, not stored.
//!
//! ## The wire
//!
//! `GET` the challenge address: a [`Challenge`], a nonce of the receiver's with a difficulty. Then
//! `POST` the report address with the body [`Built::body`]:
//!
//! ```text
//! u32 little-endian    the length of the report's JSON
//! the report's JSON    exactly the bytes `n0x feedback` shows
//! each attachment      in the order the report lists them, each exactly the size it states
//! ```
//!
//! and the headers [`NONCE_HEADER`] (the nonce, as given) and [`PROOF_HEADER`] (the counter that
//! solves it, in decimal). The proof covers the body's digest, so a solved nonce is good for that
//! one body and nothing else, and the receiver takes a nonce once whether or not it was solved.

use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

/// The schema this build writes, and the only one the receiver stores.
pub const SCHEMA: u32 = 1;

/// The header that carries the challenge's nonce back, in the hex it was given in.
pub const NONCE_HEADER: &str = "X-N0xis-Nonce";
/// The header that carries the counter solving the nonce, in decimal.
pub const PROOF_HEADER: &str = "X-N0xis-Proof";

/// The most leading zero bits a client will work for. Each bit doubles the work, and a receiver
/// asking for more than a person's machine does in a minute or so is refused rather than obeyed:
/// a client that hangs on a demand it cannot meet looks like a client that hangs. The receiver
/// refuses a configuration above it.
pub const MAX_DIFFICULTY: u32 = 28;

/// Where a person can write when nothing can be sent.
pub const CONTACT: &str = "structio.dev@gmail.com";

/// The public repository's form for a new issue.
pub const NEW_ISSUE: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/issues/new");

/// The bounds a report is held to. The client holds it to [`CLIENT_LIMITS`]; the receiver to its
/// configuration's, which may be narrower, through the same [`Report::check`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The user's text, in bytes of UTF-8.
    pub max_text_bytes: usize,
    /// One attachment, in bytes.
    pub max_attachment_bytes: u64,
    /// How many attachments. `None` is no bound of the client's own: the brief states none, and a
    /// receiver that has one refuses past it.
    pub max_attachments: Option<usize>,
}

/// What `n0x feedback` will build: text at most 64 KiB, each attachment at most 10 MiB.
pub const CLIENT_LIMITS: Limits = Limits { max_text_bytes: 64 * 1024, max_attachment_bytes: 10 * 1024 * 1024, max_attachments: None };

/// The two kinds an attachment can be, decided by its bytes and never by a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageType {
    Png,
    Jpeg,
}

impl ImageType {
    /// The type these bytes are, by their magic, or none of the two.
    pub fn of(bytes: &[u8]) -> Option<ImageType> {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(ImageType::Png)
        } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
            Some(ImageType::Jpeg)
        } else {
            None
        }
    }

    /// The extension a stored attachment of this type gets.
    pub fn extension(self) -> &'static str {
        match self {
            ImageType::Png => "png",
            ImageType::Jpeg => "jpg",
        }
    }
}

/// One attachment as the report lists it. Its bytes travel after the JSON, in this order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    #[serde(rename = "type")]
    pub kind: ImageType,
    pub size: u64,
    /// Lower-case hex.
    pub sha256: String,
}

/// A report: everything that is sent besides the attachments' bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema: u32,
    /// The version of the tool that wrote it.
    pub version: String,
    /// `std::env::consts::OS`: the family, never a release or a build.
    pub os: String,
    /// `std::env::consts::ARCH`.
    pub arch: String,
    pub text: String,
    pub attachments: Vec<Attachment>,
    /// An error the user handed over (`--with-error`): its code, and its message with every path,
    /// address, file name and quoted span replaced ([`scrub`]). Absent unless asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ReportedError>,
}

/// An error envelope's code and scrubbed message: all of it a report keeps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedError {
    pub code: String,
    pub message: String,
}

/// The longest error message a report holds, after [`scrub`]. A schema bound, the same on both sides.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 4096;
/// The longest error code: the tool's own codes are a few words of kebab case.
const MAX_ERROR_CODE_BYTES: usize = 64;

impl ReportedError {
    /// The error of an envelope the tool printed, `{"ok":false,"error":{"code":…,"message":…}}`.
    /// Only the code and the message are kept; the message is scrubbed, then cut at a word to the
    /// bound. Anything else in the envelope (a hint, a detail) is left behind.
    pub fn from_envelope(bytes: &[u8]) -> Result<ReportedError, Refusal> {
        let not = |why: &str| Refusal::NotAnErrorEnvelope(why.to_string());
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| Refusal::NotAnErrorEnvelope(format!("not JSON: {e}")))?;
        if value.get("ok") != Some(&serde_json::Value::Bool(false)) {
            return Err(not("not a refusal: `ok` is not false"));
        }
        let error = value.get("error").ok_or_else(|| not("no `error`"))?;
        let code = error.get("code").and_then(serde_json::Value::as_str).ok_or_else(|| not("no `error.code`"))?;
        if !is_error_code(code) {
            return Err(not("`error.code` is not one of the tool's codes"));
        }
        let message = error.get("message").and_then(serde_json::Value::as_str).unwrap_or("");
        Ok(ReportedError { code: code.to_string(), message: cut_at_a_word(&scrub(message), MAX_ERROR_MESSAGE_BYTES) })
    }
}

/// Kebab case, as every code the tool emits is: nothing a code could carry of a file.
fn is_error_code(code: &str) -> bool {
    !code.is_empty() && code.len() <= MAX_ERROR_CODE_BYTES && code.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `text` cut at the last whole word within `max` bytes. Whole words, so a cut never leaves a
/// fragment that [`scrub`] would read otherwise than the word it came from.
fn cut_at_a_word(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let room = max.saturating_sub(" …".len());
    let end = text.char_indices().map(|(i, c)| i + c.len_utf8()).take_while(|&e| e <= room).last().unwrap_or(0);
    let cut = &text[..end];
    let cut = match cut.rfind(char::is_whitespace) {
        Some(at) if !text[end..].starts_with(char::is_whitespace) => &cut[..at],
        _ => cut,
    };
    format!("{} …", cut.trim_end())
}

/// An error message with what could name or locate something of the user's taken out.
///
/// - a span in backticks, double quotes, or single quotes at a word's edge: `<quoted>`. The tool
///   quotes what it was given and what it found, a symbol or a string of the target among them;
/// - a word holding `/` or `\`: `<path>`;
/// - a word starting `0x`, or of four or more hex digits with a digit among them, which covers a
///   decimal number of four digits or more and a digest: `<addr>`;
/// - a word with a dot between two letters or digits that is not all digits and dots: `<file>`.
///
/// Punctuation around a word stays, and whitespace is kept as it was. What it keeps are words: the
/// tool's own wording, small numbers and the dotted versions. It runs on what it wrote and changes
/// nothing, which is how the receiver tells a scrubbed message from one that was not.
pub fn scrub(message: &str) -> String {
    let unquoted = without_quoted_spans(message);
    let mut out = String::with_capacity(unquoted.len());
    let mut word = String::new();
    for c in unquoted.chars().chain(std::iter::once(' ')) {
        if c.is_whitespace() {
            out.push_str(&scrub_word(&word));
            word.clear();
            out.push(c);
        } else {
            word.push(c);
        }
    }
    out.pop();
    out
}

fn without_quoted_spans(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let at_edge = |j: usize| j == 0 || !chars[j - 1].is_alphanumeric();
        let opens = c == '`' || c == '"' || (c == '\'' && at_edge(i));
        if opens {
            let close = (i + 1..chars.len()).find(|&j| chars[j] == c && (c != '\'' || chars.get(j + 1).is_none_or(|n| !n.is_alphanumeric())));
            if let Some(j) = close {
                out.push_str("<quoted>");
                i = j + 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

fn scrub_word(word: &str) -> String {
    let edge = |c: char| "([{<,;:.!?)]}>".contains(c);
    let core = word.trim_start_matches(edge);
    let lead = &word[..word.len() - core.len()];
    let core = core.trim_end_matches(edge);
    let tail = &word[lead.len() + core.len()..];
    let replaced = if core.contains(['/', '\\']) {
        Some("<path>")
    } else if is_address(core) {
        Some("<addr>")
    } else if is_file_name(core) {
        Some("<file>")
    } else {
        None
    };
    match replaced {
        Some(r) => format!("{lead}{r}{tail}"),
        None => word.to_string(),
    }
}

fn is_address(core: &str) -> bool {
    let hex = core.strip_prefix("0x").or_else(|| core.strip_prefix("0X"));
    if let Some(rest) = hex {
        return rest.starts_with(|c: char| c.is_ascii_hexdigit());
    }
    core.len() >= 4 && core.chars().all(|c| c.is_ascii_hexdigit()) && core.chars().any(|c| c.is_ascii_digit())
}

fn is_file_name(core: &str) -> bool {
    let b: Vec<char> = core.chars().collect();
    let dotted = (1..b.len().saturating_sub(1)).any(|i| b[i] == '.' && b[i - 1].is_alphanumeric() && b[i + 1].is_alphanumeric());
    dotted && !core.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Why a report is not one this side accepts. Each has its own code, for the door's envelope and
/// for the receiver's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    EmptyText,
    TextTooLong { bytes: usize, max: usize },
    TooManyAttachments { count: usize, max: usize },
    AttachmentTooLarge { index: usize, size: u64, max: u64 },
    /// Neither PNG nor JPEG by its bytes.
    NotAnImage { index: usize },
    /// The bytes are the other type than the report states.
    TypeMismatch { index: usize },
    DigestMismatch { index: usize },
    UnknownSchema(u32),
    /// The body is not a framed report: short, long, or JSON that is not a [`Report`].
    Malformed(String),
    /// What was handed to `--with-error` is not an envelope of a refusal.
    NotAnErrorEnvelope(String),
    /// A reported error whose code is not one of the tool's, whose message is past the bound, or
    /// that still holds what [`scrub`] takes out.
    UnscrubbedError,
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::EmptyText => "empty-text",
            Refusal::TextTooLong { .. } => "text-too-long",
            Refusal::TooManyAttachments { .. } => "too-many-attachments",
            Refusal::AttachmentTooLarge { .. } => "attachment-too-large",
            Refusal::NotAnImage { .. } => "not-an-image",
            Refusal::TypeMismatch { .. } => "type-mismatch",
            Refusal::DigestMismatch { .. } => "digest-mismatch",
            Refusal::UnknownSchema(_) => "unknown-schema",
            Refusal::Malformed(_) => "malformed-report",
            Refusal::NotAnErrorEnvelope(_) => "not-an-error-envelope",
            Refusal::UnscrubbedError => "unscrubbed-error",
        }
    }

    /// Whether this is a bound being exceeded, which the receiver answers with 413.
    pub fn is_size(&self) -> bool {
        matches!(self, Refusal::TextTooLong { .. } | Refusal::TooManyAttachments { .. } | Refusal::AttachmentTooLarge { .. })
    }

    /// Whether this is an attachment of a type not taken, which the receiver answers with 415.
    pub fn is_type(&self) -> bool {
        matches!(self, Refusal::NotAnImage { .. } | Refusal::TypeMismatch { .. })
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Attachments are named by their place on the command line, counted from 1, so that the
        // message names nothing the user did not type.
        match self {
            Refusal::EmptyText => write!(f, "the text is empty: a report says something"),
            Refusal::TextTooLong { bytes, max } => write!(f, "the text is {bytes} bytes, more than the {max} a report holds"),
            Refusal::TooManyAttachments { count, max } => write!(f, "{count} attachments, more than the {max} taken"),
            Refusal::AttachmentTooLarge { index, size, max } => {
                write!(f, "attachment {} is {size} bytes, more than the {max} taken", index + 1)
            }
            Refusal::NotAnImage { index } => write!(f, "attachment {} is neither PNG nor JPEG by its bytes", index + 1),
            Refusal::TypeMismatch { index } => write!(f, "attachment {} is not the type the report states", index + 1),
            Refusal::DigestMismatch { index } => write!(f, "attachment {} is not the bytes the report's digest states", index + 1),
            Refusal::UnknownSchema(n) => write!(f, "schema {n} is not one this side reads (it reads {SCHEMA})"),
            Refusal::Malformed(why) => write!(f, "not a report: {why}"),
            Refusal::NotAnErrorEnvelope(why) => write!(f, "not an error envelope of the tool's: {why}"),
            Refusal::UnscrubbedError => write!(f, "the reported error is not a code and a scrubbed message within the bound"),
        }
    }
}

impl Report {
    /// Whether this report, with these bytes for its attachments, is within `limits` and says
    /// what its attachments are. The one check both sides run.
    pub fn check(&self, attachments: &[&[u8]], limits: &Limits) -> Result<(), Refusal> {
        if self.schema != SCHEMA {
            return Err(Refusal::UnknownSchema(self.schema));
        }
        if self.text.trim().is_empty() {
            return Err(Refusal::EmptyText);
        }
        if let Some(e) = &self.error
            && (!is_error_code(&e.code) || e.message.len() > MAX_ERROR_MESSAGE_BYTES || scrub(&e.message) != e.message)
        {
            return Err(Refusal::UnscrubbedError);
        }
        if self.text.len() > limits.max_text_bytes {
            return Err(Refusal::TextTooLong { bytes: self.text.len(), max: limits.max_text_bytes });
        }
        if let Some(max) = limits.max_attachments
            && self.attachments.len() > max
        {
            return Err(Refusal::TooManyAttachments { count: self.attachments.len(), max });
        }
        if attachments.len() != self.attachments.len() {
            return Err(Refusal::Malformed(format!("{} attachments listed, {} sent", self.attachments.len(), attachments.len())));
        }
        for (index, (listed, bytes)) in self.attachments.iter().zip(attachments).enumerate() {
            let size = bytes.len() as u64;
            if size > limits.max_attachment_bytes {
                return Err(Refusal::AttachmentTooLarge { index, size, max: limits.max_attachment_bytes });
            }
            if size != listed.size {
                return Err(Refusal::Malformed(format!("attachment {} states {} bytes and is {size}", index + 1, listed.size)));
            }
            match ImageType::of(bytes) {
                None => return Err(Refusal::NotAnImage { index }),
                Some(kind) if kind != listed.kind => return Err(Refusal::TypeMismatch { index }),
                Some(_) => {}
            }
            if sha256_hex(bytes) != listed.sha256 {
                return Err(Refusal::DigestMismatch { index });
            }
        }
        Ok(())
    }
}

/// A report as it is shown and as it is sent: one serialization, framed once.
#[derive(Clone, Debug)]
pub struct Built {
    report: Report,
    json: String,
    body: Vec<u8>,
}

impl Built {
    /// The report's JSON: the bytes the door shows, and the bytes the body carries.
    pub fn json(&self) -> &str {
        &self.json
    }

    /// What is posted: the JSON, framed with the attachments' bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn report(&self) -> &Report {
        &self.report
    }
}

/// The report of `text` with `attachments`, held to [`CLIENT_LIMITS`]. Each attachment's type is
/// read from its bytes. `version` is the door's own: the tool's, not this crate's.
pub fn build(text: &str, attachments: &[Vec<u8>], error: Option<ReportedError>, version: &str) -> Result<Built, Refusal> {
    let mut listed = Vec::with_capacity(attachments.len());
    for (index, bytes) in attachments.iter().enumerate() {
        let size = bytes.len() as u64;
        // The size first: a file past the bound is refused as that, whatever it holds.
        if size > CLIENT_LIMITS.max_attachment_bytes {
            return Err(Refusal::AttachmentTooLarge { index, size, max: CLIENT_LIMITS.max_attachment_bytes });
        }
        let kind = ImageType::of(bytes).ok_or(Refusal::NotAnImage { index })?;
        listed.push(Attachment { kind, size, sha256: sha256_hex(bytes) });
    }
    let report = Report {
        schema: SCHEMA,
        version: version.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        text: text.to_string(),
        attachments: listed,
        error,
    };
    let slices: Vec<&[u8]> = attachments.iter().map(Vec::as_slice).collect();
    report.check(&slices, &CLIENT_LIMITS)?;
    let json = serde_json::to_string(&report).map_err(|e| Refusal::Malformed(e.to_string()))?;
    let body = frame(json.as_bytes(), &slices);
    Ok(Built { report, json, body })
}

/// The body for a report's JSON and its attachments' bytes.
pub fn frame(json: &[u8], attachments: &[&[u8]]) -> Vec<u8> {
    let total = 4 + json.len() + attachments.iter().map(|a| a.len()).sum::<usize>();
    let mut body = Vec::with_capacity(total);
    // A JSON of 4 GiB is not a report; the client's bounds stop far short of it.
    body.extend_from_slice(&u32::try_from(json.len()).unwrap_or(u32::MAX).to_le_bytes());
    body.extend_from_slice(json);
    for a in attachments {
        body.extend_from_slice(a);
    }
    body
}

/// A body taken apart: the report, the exact JSON it was read from, and each attachment's bytes.
#[derive(Debug)]
pub struct Unframed<'a> {
    pub report: Report,
    pub json: &'a [u8],
    pub attachments: Vec<&'a [u8]>,
}

/// Take a body apart, refusing one whose parts do not add up to it exactly. Nothing is checked
/// against limits here: that is [`Report::check`].
pub fn unframe(body: &[u8]) -> Result<Unframed<'_>, Refusal> {
    let malformed = |why: &str| Refusal::Malformed(why.to_string());
    let (head, rest) = body.split_first_chunk::<4>().ok_or_else(|| malformed("shorter than its length prefix"))?;
    let json_len = u32::from_le_bytes(*head) as usize;
    if json_len > rest.len() {
        return Err(malformed("the JSON's length runs past the body"));
    }
    let (json, mut rest) = rest.split_at(json_len);
    let report: Report = serde_json::from_slice(json).map_err(|e| Refusal::Malformed(e.to_string()))?;
    let mut attachments = Vec::with_capacity(report.attachments.len().min(64));
    for (index, listed) in report.attachments.iter().enumerate() {
        let size = usize::try_from(listed.size).ok().filter(|&s| s <= rest.len());
        let Some(size) = size else {
            return Err(Refusal::Malformed(format!("attachment {} runs past the body", index + 1)));
        };
        let (bytes, after) = rest.split_at(size);
        attachments.push(bytes);
        rest = after;
    }
    if !rest.is_empty() {
        return Err(malformed("bytes after the last attachment"));
    }
    Ok(Unframed { report, json, attachments })
}

/// What `GET` on the challenge address answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub schema: u32,
    /// 32 bytes, lower-case hex.
    pub nonce: String,
    /// Leading zero bits the work must have.
    pub difficulty: u32,
    /// How long the nonce is taken for, from when it was issued.
    pub expires_in_seconds: u64,
}

/// What the receiver answers a stored report with: the name to give when asking for its deletion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    pub id: String,
}

/// The work for `counter`: sha256 over the nonce, the body's digest and the counter.
fn work(nonce: &[u8; 32], body_digest: &[u8], counter: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 32 + 8);
    input.extend_from_slice(nonce);
    input.extend_from_slice(body_digest);
    input.extend_from_slice(&counter.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, &input).as_ref());
    out
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            return bits + byte.leading_zeros();
        }
    }
    bits
}

/// The first counter that solves `nonce` for `body` at `difficulty`, or none for a difficulty
/// past [`MAX_DIFFICULTY`], which is refused rather than worked for.
pub fn solve(nonce: &[u8; 32], body: &[u8], difficulty: u32) -> Option<u64> {
    if difficulty > MAX_DIFFICULTY {
        return None;
    }
    let body_digest = digest(&SHA256, body);
    (0..=u64::MAX).find(|&counter| leading_zero_bits(&work(nonce, body_digest.as_ref(), counter)) >= difficulty)
}

/// Whether `counter` solves `nonce` for `body` at `difficulty`.
pub fn verify(nonce: &[u8; 32], body: &[u8], difficulty: u32, counter: u64) -> bool {
    let body_digest = digest(&SHA256, body);
    leading_zero_bits(&work(nonce, body_digest.as_ref(), counter)) >= difficulty
}

/// The sha256 of `bytes`, in lower-case hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(digest(&SHA256, bytes).as_ref())
}

/// Lower-case hex.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Exactly 32 bytes of hex, or nothing.
pub fn nonce_from_hex(text: &str) -> Option<[u8; 32]> {
    let text = text.as_bytes();
    if text.len() != 64 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_chunks::<2>().0) {
        *slot = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

/// A prefilled form for a new issue in the public repository, with the report's text and the
/// version, OS and architecture it states. Attachments cannot travel in a link.
///
/// A link longer than [`ISSUE_LINK_MAX`] is not opened by the forge, so past it the text is left
/// out and the link carries the version line alone: the text is then pasted from the saved file.
pub fn issue_link(report: &Report) -> IssueLink {
    let about = format!("n0xis {}, {} {}", report.version, report.os, report.arch);
    let full = format!("{NEW_ISSUE}?title={}&body={}", percent(&title_of(&report.text)), percent(&format!("{}\n\n{about}", report.text)));
    if full.len() <= ISSUE_LINK_MAX {
        return IssueLink { url: full, carries_text: true };
    }
    IssueLink { url: format!("{NEW_ISSUE}?title=Feedback&body={}", percent(&about)), carries_text: false }
}

/// A link to a new issue, and whether it carries the report's text.
#[derive(Clone, Debug, Serialize)]
pub struct IssueLink {
    pub url: String,
    pub carries_text: bool,
}

/// The longest link the forge is known to open. GitHub answers 414 to request lines past about
/// 8 KiB; this stays under it.
pub const ISSUE_LINK_MAX: usize = 8000;

fn title_of(text: &str) -> String {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("Feedback");
    let mut title: String = line.chars().take(80).collect();
    if title.len() < line.len() {
        title.push('…');
    }
    title
}

/// Percent-encoding for a query value: everything but the unreserved characters.
fn percent(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(extra: usize) -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.resize(8 + extra, 7);
        bytes
    }

    #[test]
    fn a_body_comes_apart_into_the_json_that_was_shown() {
        let jpeg = vec![0xff, 0xd8, 0xff, 0xe0, 1, 2, 3];
        let built = build("it broke", &[png(10), jpeg.clone()], None, "9.9.9").expect("builds");
        let parts = unframe(built.body()).expect("unframes");
        assert_eq!(parts.json, built.json().as_bytes());
        assert_eq!(parts.attachments, vec![png(10).as_slice(), jpeg.as_slice()]);
        assert_eq!(&parts.report, built.report());
        parts.report.check(&parts.attachments, &CLIENT_LIMITS).expect("checks");
    }

    #[test]
    fn the_limits_hold_at_their_edge() {
        let max = CLIENT_LIMITS.max_text_bytes;
        build(&"a".repeat(max), &[], None, "1.0.0").expect("the bound itself is taken");
        assert_eq!(build(&"a".repeat(max + 1), &[], None, "1.0.0").unwrap_err(), Refusal::TextTooLong { bytes: max + 1, max });
        let at = CLIENT_LIMITS.max_attachment_bytes as usize;
        build("x", &[png(at - 8)], None, "1.0.0").expect("an attachment at the bound is taken");
        let over = build("x", &[png(at - 7)], None, "1.0.0").unwrap_err();
        assert_eq!(over, Refusal::AttachmentTooLarge { index: 0, size: at as u64 + 1, max: at as u64 });
        assert_eq!(build("  \n", &[], None, "1.0.0").unwrap_err(), Refusal::EmptyText);
    }

    #[test]
    fn a_type_is_its_bytes_and_never_its_name() {
        assert_eq!(build("x", &[b"GIF89a....".to_vec()], None, "1.0.0").unwrap_err(), Refusal::NotAnImage { index: 0 });
        // PNG bytes listed as JPEG: refused by the receiver's side of the same check.
        let built = build("x", &[png(4)], None, "1.0.0").expect("builds");
        let mut report = built.report().clone();
        report.attachments[0].kind = ImageType::Jpeg;
        assert_eq!(report.check(&[&png(4)], &CLIENT_LIMITS).unwrap_err(), Refusal::TypeMismatch { index: 0 });
        report.attachments[0].kind = ImageType::Png;
        let mut other = png(4);
        other[10] ^= 1;
        assert_eq!(report.check(&[&other], &CLIENT_LIMITS).unwrap_err(), Refusal::DigestMismatch { index: 0 });
    }

    #[test]
    fn a_report_with_anything_else_in_it_is_not_one() {
        let built = build("x", &[], None, "1.0.0").expect("builds");
        let json = built.json().replacen('{', r#"{"path":"/home/u/target.bin","#, 1);
        let refused = unframe(&frame(json.as_bytes(), &[])).unwrap_err();
        assert_eq!(refused.code(), "malformed-report", "{refused}");
    }

    #[test]
    fn a_body_that_does_not_add_up_is_refused() {
        let built = build("x", &[png(4)], None, "1.0.0").expect("builds");
        let body = built.body();
        assert!(unframe(&body[..body.len() - 1]).is_err(), "short by a byte");
        let mut long = body.to_vec();
        long.push(0);
        assert!(unframe(&long).is_err(), "long by a byte");
        assert!(unframe(&[1, 0]).is_err(), "no length");
        let mut lying = body.to_vec();
        lying[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unframe(&lying).is_err(), "a length past the body");
    }

    #[test]
    fn the_proof_of_work_verifies_and_a_wrong_one_fails() {
        let nonce = [9u8; 32];
        let body = b"a body";
        let difficulty = 12;
        let counter = solve(&nonce, body, difficulty).expect("within the bound");
        // From Python's hashlib over the same layout (nonce, sha256(body), counter as u64 LE), so the
        // layout the receiver and every shipped client must agree on is pinned by a second reader:
        // sha256 = 000eddcd…, 12 leading zero bits, and no counter below it reaches 12.
        assert_eq!(counter, 2932);
        assert!(verify(&nonce, body, difficulty, counter));
        // Calibrated by the counters before it: none of them solves it, or `solve` would have stopped there.
        for wrong in 0..counter {
            assert!(!verify(&nonce, body, difficulty, wrong), "counter {wrong} below the first solution verified");
        }
        // The proof is of this nonce and this body.
        let other_nonce_fails = (0..64).filter(|n| verify(&[*n as u8; 32], body, difficulty, counter)).count();
        assert!(other_nonce_fails < 2, "the proof held for {other_nonce_fails} of 64 other nonces at 1 in 4096");
        let other_body_fails = (0..64).filter(|n| verify(&nonce, &[*n as u8], difficulty, counter)).count();
        assert!(other_body_fails < 2, "the proof held for {other_body_fails} of 64 other bodies at 1 in 4096");
        assert_eq!(solve(&nonce, body, MAX_DIFFICULTY + 1), None, "a demand past the bound is refused");
    }

    /// A message holding everything a scrub is for, planted.
    const PLANTED: &str = "cannot read /home/u/secret-k2/zz-planted-target-5521.so at 0x10e9 (4329, rva 10E9): no symbol `n0x_pick` \
                           in zz-planted-target-5521.so, nor \"n0xis-planted-ascii-7f3a\" nor 'planted_name_q8'; C:\\Users\\u\\x.dll; \
                           digest 3b1f00aa9c; it's 3 of 5 in 0.3.9";

    #[test]
    fn a_scrubbed_message_holds_no_path_address_name_or_quoted_span() {
        let scrubbed = scrub(PLANTED);
        for needle in ["/home", "secret-k2", "zz-planted", ".so", "0x10e9", "4329", "10E9", "n0x_pick", "7f3a", "planted_name_q8", "Users", "x.dll", "3b1f00aa9c"] {
            assert!(!scrubbed.contains(needle), "{needle} is in {scrubbed:?}");
        }
        // The tool's own words stay, with small numbers, a version and an apostrophe that quotes nothing.
        for kept in ["cannot read", "<path>", "<addr>", "<file>", "<quoted>", "no symbol", "it's 3 of 5 in 0.3.9"] {
            assert!(scrubbed.contains(kept), "{kept} is not in {scrubbed:?}");
        }
        assert_eq!(scrub(&scrubbed), scrubbed, "a scrub of a scrubbed message changes nothing");
    }

    #[test]
    fn an_error_is_taken_from_a_refusal_envelope_and_only_its_code_and_message() {
        let envelope = serde_json::json!({ "ok": false, "error": { "code": "not-in-function", "message": PLANTED, "hint": "try /home/u/secret-k2" } });
        let e = ReportedError::from_envelope(envelope.to_string().as_bytes()).expect("an envelope");
        assert_eq!((e.code.as_str(), e.message.as_str()), ("not-in-function", scrub(PLANTED).as_str()));
        let built = build("x", &[], Some(e), "1.0.0").expect("builds");
        assert!(!built.json().contains("secret-k2") && !built.json().contains("hint"), "{}", built.json());
        let refusal = |v: serde_json::Value| ReportedError::from_envelope(v.to_string().as_bytes()).unwrap_err().code();
        assert_eq!(refusal(serde_json::json!({ "ok": true, "data": {} })), "not-an-error-envelope");
        assert_eq!(refusal(serde_json::json!({ "ok": false, "error": { "code": "/home/u/x.so", "message": "m" } })), "not-an-error-envelope");
        assert_eq!(ReportedError::from_envelope(b"not json").unwrap_err().code(), "not-an-error-envelope");
        let long = ReportedError::from_envelope(serde_json::json!({ "ok": false, "error": { "code": "c", "message": "word ".repeat(2000) } }).to_string().as_bytes()).expect("cut");
        assert!(long.message.len() <= MAX_ERROR_MESSAGE_BYTES && long.message.ends_with("word …"), "{}", &long.message[long.message.len() - 20..]);
    }

    #[test]
    fn a_report_whose_error_was_not_scrubbed_is_refused() {
        let mut report = build("x", &[], None, "1.0.0").expect("builds").report().clone();
        report.error = Some(ReportedError { code: "c".into(), message: "at /home/u/target.bin".into() });
        assert_eq!(report.check(&[], &CLIENT_LIMITS).unwrap_err(), Refusal::UnscrubbedError);
        report.error = Some(ReportedError { code: "c".into(), message: scrub("at /home/u/target.bin") });
        report.check(&[], &CLIENT_LIMITS).expect("scrubbed");
    }

    #[test]
    fn the_issue_link_carries_the_text_until_it_cannot() {
        let short = build("the decompiler hangs", &[], None, "1.2.3").expect("builds");
        let link = issue_link(short.report());
        assert!(link.carries_text && link.url.contains("the%20decompiler%20hangs") && link.url.contains("n0xis%201.2.3"), "{}", link.url);
        let long = build(&"word ".repeat(4000), &[], None, "1.2.3").expect("builds");
        let link = issue_link(long.report());
        assert!(!link.carries_text && link.url.len() <= ISSUE_LINK_MAX && link.url.contains("n0xis%201.2.3"), "{}", link.url);
    }
}
