// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! # n0xis-update: the tool offers, the user decides
//!
//! The only network client in the tree, and an adapter: `n0xis-contracts`, `-arch` and `-core`
//! never depend on it (`scripts/check_boundary.sh` holds that) and only the two doors link it, so
//! no analysis path can reach the network. `docs/design/UPDATE.md` is the specification.
//!
//! **The client asks; it never derives.** A copy in the field cannot be repaired by shipping a
//! repair, so everything about where a file comes from is read from a signed manifest. What is
//! frozen here is the manifest's address ([`MANIFEST_ADDRESSES`]), the key ([`RELEASE_PUBLIC_KEY`])
//! and the meaning of the few manifest fields read. Every field not read is ignored, and a component
//! this client does not know is left alone, so the manifest can grow without stranding anyone.

pub mod config;
mod install;
mod manifest;
mod net;
pub mod notice;
mod trust;

use std::path::PathBuf;

use semver::Version;
use serde::Serialize;

pub use install::{Outcome, RollbackReport, Skipped, UpdateReport, rollback};
pub use manifest::{Entry, Manifest, platform};
pub use net::{Limits, Transport};
pub use trust::{RELEASE_PUBLIC_KEY, Trust};

/// Where the manifest is asked for, every one of them, unless the configuration's override replaces them.
///
/// The one thing about releases a shipped client is frozen to, and the repository has moved before,
/// so the first is a domain the project controls and the second is the fallback. A dead address is
/// routine and says nothing: another answering is a success with no notice.
pub const MANIFEST_ADDRESSES: [&str; 2] =
    ["https://updates.structio.dev/n0xis/manifest.json", "https://github.com/Structio-labs/N0xis/releases/latest/download/manifest.json"];

/// The detached signature sits beside the manifest under this suffix, wherever the manifest is.
pub const SIGNATURE_SUFFIX: &str = ".sig";

/// Why something was not installed. Each reason has its own code, because an unperformed check must
/// never read as a passed one, and a script or the GUI can only keep them apart if they differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Why {
    /// No address answered at all.
    ManifestUnavailable,
    /// An address answered with a manifest, and no signature could be had for it.
    NoSignature,
    /// Signed by a key this client trusts, but not a manifest it can read.
    BadManifest,
    /// A signature came, and none of them verifies.
    BadSignature,
    /// This build holds no usable key, so nothing can be verified (the placeholder, or a typo in the key).
    NoReleaseKey,
    NoEntry,
    NoDigest,
    OlderVersion,
    DownloadFailed,
    SizeMismatch,
    DigestMismatch,
    NotWritable,
    InstallFailed,
    NoPrevious,
    ConfigUnreadable,
    UnknownSetting,
    BadSettingValue,
    /// Another run holds the lock beside the binary.
    UpdateInProgress,
    /// The running component's new file, checked and signed, did not answer `--version` as it must.
    DoesNotRun,
    /// A file to replace, or a sibling of it, is something other than a regular file.
    NotARegularFile,
    /// What is kept for `--rollback` is not what its record says, or there is no record of it.
    PreviousDoesNotMatch,
    /// The configuration directory belongs to someone else (`config::user_dir`).
    ConfigNotYours,
    /// The target of `--rollback` is not the file the last update left there.
    NotWhatWasInstalled,
    /// A lock or a hold beside a file is a link, a FIFO or another user's, or a hold does not read.
    NotOurs,
    /// `--rollback` was given something other than a bare file name.
    NotABareName,
    /// `update.auto` left a version alone that `--rollback` went back from. Only ever in `skipped`.
    Held,
}

impl Why {
    /// The `error.code` of the envelope.
    pub fn code(self) -> &'static str {
        match self {
            Why::ManifestUnavailable => "manifest-unavailable",
            Why::NoSignature => "no-signature",
            Why::BadManifest => "bad-manifest",
            Why::BadSignature => "bad-signature",
            Why::NoReleaseKey => "no-release-key",
            Why::NoEntry => "no-entry",
            Why::NoDigest => "no-digest",
            Why::OlderVersion => "older-version",
            Why::DownloadFailed => "download-failed",
            Why::SizeMismatch => "size-mismatch",
            Why::DigestMismatch => "digest-mismatch",
            Why::NotWritable => "not-writable",
            Why::InstallFailed => "install-failed",
            Why::NoPrevious => "no-previous",
            Why::ConfigUnreadable => "config-unreadable",
            Why::UnknownSetting => "unknown-setting",
            Why::BadSettingValue => "bad-setting-value",
            Why::UpdateInProgress => "update-in-progress",
            Why::DoesNotRun => "does-not-run",
            Why::NotARegularFile => "not-a-regular-file",
            Why::PreviousDoesNotMatch => "previous-does-not-match",
            Why::ConfigNotYours => "config-not-yours",
            Why::NotWhatWasInstalled => "not-what-was-installed",
            Why::NotOurs => "not-ours",
            Why::NotABareName => "not-a-bare-name",
            Why::Held => "held",
        }
    }
}

/// A refusal: what the door prints as `{ok:false, error}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub why: Why,
    pub message: String,
    pub hint: Option<String>,
    /// Where some files moved and some did not, each one's own result. Empty when nothing moved.
    pub components: Vec<Outcome>,
}

impl Refusal {
    pub fn new(why: Why, message: impl Into<String>) -> Self {
        Refusal { why, message: message.into(), hint: None, components: Vec::new() }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// One address that was asked and did not give a manifest to use.
#[derive(Clone, Debug, Serialize)]
pub struct Tried {
    pub address: String,
    pub code: &'static str,
    pub message: String,
}

/// A manifest that verified, and where it came from.
#[derive(Debug)]
pub struct Found {
    pub manifest: Manifest,
    pub address: String,
    pub tried: Vec<Tried>,
}

/// What `n0x update --check` answers.
#[derive(Clone, Debug, Serialize)]
pub struct CheckReport {
    pub current: String,
    pub latest: String,
    /// Newer than this build, with an entry for this component and platform that could be installed.
    pub available: bool,
    /// Newer, but `n0x update` would refuse, with the code it would refuse with.
    pub blocked: Option<&'static str>,
    pub address: String,
    /// Addresses asked that gave no manifest to use, beside the one that did. A dead address lands
    /// here and nowhere else.
    pub tried: Vec<Tried>,
}

/// Everything one update operation stands on, so that a test hands it a planted server, a key made
/// for the test and a file that is not the running binary, through the code the door runs.
#[derive(Debug)]
pub struct Updater {
    pub component: String,
    pub platform: String,
    pub current: Version,
    /// The file to replace.
    pub exe: PathBuf,
    /// The user's explicit override. When set it is the only address: nothing else is asked, whatever
    /// it answers, and a dead or bad one is a refusal.
    pub pin: Option<String>,
    /// Asked, every one of them, when there is no pin.
    pub addresses: Vec<String>,
    pub trust: Trust,
    pub transport: Transport,
    /// Where a next key named by a signed manifest is remembered.
    pub config_dir: Option<PathBuf>,
}

impl Updater {
    /// The running binary, as `n0x update` and the daily check see it.
    ///
    /// A broken configuration file is a refusal rather than a fallback to the built-in addresses,
    /// because the file may hold an override the user set on purpose.
    pub fn for_running(component: &str, version: &str) -> Result<Updater, Refusal> {
        let config_dir = config::user_dir();
        let settings = match &config_dir {
            Some(dir) => config::Settings::load(dir)?,
            None => config::Settings::default(),
        };
        let exe = std::env::current_exe()
            .map_err(|e| Refusal::new(Why::InstallFailed, format!("cannot tell where this binary is: {e}")))?;
        let current = Version::parse(version).map_err(|e| Refusal::new(Why::InstallFailed, format!("this build's own version {version:?}: {e}")))?;
        Ok(Updater {
            component: component.to_string(),
            platform: platform(),
            current,
            exe,
            pin: settings.manifest_url,
            addresses: MANIFEST_ADDRESSES.iter().map(|a| a.to_string()).collect(),
            trust: Trust::of_release(config_dir.as_deref()),
            transport: Transport::standard(version),
            config_dir,
        })
    }

    /// The manifest to act on: the pin's, or else the highest version that verifies among all the
    /// frozen addresses.
    ///
    /// All of them, because the first that verifies is not the newest. A replayed old signed manifest
    /// at the first address would otherwise freeze every copy, with the second never asked. Any failure
    /// moves on, a bad signature too: a domain that lapsed and was taken over answers with something
    /// unsigned, and going on costs nothing, since whatever the next says must verify just the same.
    /// A failure beside a success stays in `tried` and is no refusal.
    ///
    /// A pin replaces them: someone who pinned a mirror meant for nothing public to be asked, and a
    /// pin that fell through once installed from where it was meant not to.
    pub fn fetch_manifest(&self) -> Result<Found, Refusal> {
        let addresses = self.pin.as_ref().map_or(self.addresses.as_slice(), std::slice::from_ref);
        let mut tried = Vec::new();
        let mut worst: Option<Why> = None;
        let mut best: Option<(Manifest, &String)> = None;
        for address in addresses {
            match self.fetch_one(address) {
                Ok(manifest) => {
                    if best.as_ref().is_none_or(|(held, _)| manifest.version > held.version) {
                        best = Some((manifest, address));
                    }
                }
                Err(r) => {
                    worst = Some(worst.map_or(r.why, |w| w.max(r.why)));
                    tried.push(Tried { address: address.clone(), code: r.why.code(), message: r.message });
                }
            }
        }
        if let Some((manifest, address)) = best {
            return Ok(Found { manifest, address: address.clone(), tried });
        }
        // Reported as the most serious thing any address did: a dead first address must not hide a
        // bad signature at the second, and `Why`'s order is that seriousness.
        let why = worst.unwrap_or(Why::ManifestUnavailable);
        let detail: Vec<String> = tried.iter().map(|t| format!("{}: {}", t.address, t.message)).collect();
        let refusal = Refusal::new(why, format!("no manifest that can be used ({})", detail.join("; ")));
        Err(if self.pin.is_some() { refusal.with_hint("update.manifest_url is the only address while it is set; n0x config set update.manifest_url \"\" clears it") } else { refusal })
    }

    fn fetch_one(&self, address: &str) -> Result<Manifest, Refusal> {
        let bytes = self.transport.get_manifest(address)?;
        let signature = self.transport.get_signature(&format!("{address}{SIGNATURE_SUFFIX}"))?;
        // Before a byte of it is parsed: nothing an unverified file says is looked at.
        self.trust.verify(&bytes, &signature)?;
        let manifest = Manifest::parse(&bytes)?;
        if let Some(key) = manifest.next_key {
            self.trust.remember(self.config_dir.as_deref(), &bytes, &signature, key);
        }
        Ok(manifest)
    }

    /// `n0x update --check`.
    pub fn check(&self) -> Result<CheckReport, Refusal> {
        let found = self.fetch_manifest()?;
        Ok(self.report(&found))
    }

    pub(crate) fn report(&self, found: &Found) -> CheckReport {
        let newer = found.manifest.version > self.current;
        let blocked = if newer {
            match found.manifest.entry(&self.component, &self.platform) {
                Ok(_) => None,
                Err(r) => Some(r.why.code()),
            }
        } else {
            None
        };
        CheckReport {
            current: self.current.to_string(),
            latest: found.manifest.version.to_string(),
            available: newer && blocked.is_none(),
            blocked,
            address: found.address.clone(),
            tried: found.tried.clone(),
        }
    }
}

/// Lower-case hex, which the manifest and the signature file are written in.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Exactly `N` bytes of hex, or nothing.
pub(crate) fn from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.as_bytes();
    if text.len() != N * 2 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(text.as_chunks::<2>().0) {
        *slot = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

/// Write a file by rename, so a reader sees the old contents or the new and never half of one.
///
/// The temporary is opened `create_new`, so a link planted at its name is never followed: this write
/// fails instead, which costs a stamp or a remembered key and no one's file.
pub(crate) fn write_by_rename(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut temp = path.as_os_str().to_owned();
    temp.push(format!(".tmp-{}", std::process::id()));
    let temp = PathBuf::from(temp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .and_then(|mut file| std::io::Write::write_all(&mut file, bytes))
        .and_then(|()| std::fs::rename(&temp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}
