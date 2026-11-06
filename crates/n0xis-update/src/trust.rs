// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Which keys may sign a manifest, and the check.

use std::path::Path;

use ring::signature::{ED25519, UnparsedPublicKey};

use crate::{Refusal, Why, from_hex, to_hex, write_by_rename};

/// The release's ed25519 public key, 64 hex digits; the private key never leaves the owner's machine.
///
/// **This placeholder is not hex, on purpose: a build that still holds it refuses every manifest.**
/// All zeros would parse, and a key of small order is one a signature can be forged against, so a
/// placeholder that looks like a key would be a hole rather than a refusal. `scripts/release.py`
/// refuses to publish while this holds it, or a key that is not the signing key's.
pub const RELEASE_PUBLIC_KEY: &str = "PLACEHOLDER: the release public key goes here, and until then every manifest is refused";

/// Where a next key named by a signed manifest is remembered, in the user's configuration directory.
const REMEMBERED: &str = "update-keys.json";

/// The keys a signature is checked against.
#[derive(Debug)]
pub struct Trust {
    keys: Vec<[u8; 32]>,
}

impl Trust {
    /// The built-in key, and any next key a manifest signed by it has named.
    ///
    /// With no usable built-in key the set is empty and stays so, whatever the file says: a chain
    /// has to start at a key in the binary, or the placeholder would not fail closed.
    pub fn of_release(config_dir: Option<&Path>) -> Trust {
        Self::rooted_at(RELEASE_PUBLIC_KEY, config_dir)
    }

    /// The same rule from any constant, which is how the placeholder's refusal is tested through
    /// the path a release takes.
    pub fn rooted_at(constant: &str, config_dir: Option<&Path>) -> Trust {
        let Some(root) = from_hex::<32>(constant) else { return Trust { keys: Vec::new() } };
        let mut keys = vec![root];
        keys.extend(config_dir.map(remembered).unwrap_or_default());
        Trust { keys }
    }

    /// Exactly these keys.
    pub fn of_keys(keys: &[[u8; 32]]) -> Trust {
        Trust { keys: keys.to_vec() }
    }

    /// True when no key is held, so nothing can verify.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Check `manifest` against the detached signature file.
    ///
    /// The file is lines of hex, each one signature, and any line verifying under any key held is
    /// enough. So during a change of key a release can carry both signatures, and a client that
    /// never saw the manifest naming the new key still verifies by the old one. A line that does
    /// not read as a signature is skipped, so a later form can sit beside these.
    pub fn verify(&self, manifest: &[u8], signature_file: &[u8]) -> Result<(), Refusal> {
        if self.keys.is_empty() {
            return Err(Refusal::new(Why::NoReleaseKey, "this build holds no release key, so no manifest can be verified")
                .with_hint("fetch the file by hand from the releases page and check it against sha256sums.txt"));
        }
        let text = String::from_utf8_lossy(signature_file);
        let signatures: Vec<[u8; 64]> = text.lines().filter_map(|line| from_hex::<64>(line.trim())).collect();
        if signatures.is_empty() {
            return Err(Refusal::new(Why::NoSignature, "the signature file holds no signature"));
        }
        let verifies = |key: &[u8; 32], sig: &[u8; 64]| UnparsedPublicKey::new(&ED25519, key).verify(manifest, sig).is_ok();
        if self.keys.iter().any(|key| signatures.iter().any(|sig| verifies(key, sig))) {
            return Ok(());
        }
        Err(Refusal::new(Why::BadSignature, "the manifest's signature does not verify under any key this build trusts"))
    }

    /// Keep a next key named by a manifest that verified, so a later manifest signed by it verifies.
    ///
    /// The file sits in the user's own directory, so it gives nothing to anyone who could not already
    /// replace the user's binary. A failed write costs only the change of key, which a co-signed
    /// release or a hand download still gets past, so it does not fail the check that found the key.
    pub fn remember(&self, config_dir: Option<&Path>, key: [u8; 32]) {
        let Some(dir) = config_dir else { return };
        if self.keys.contains(&key) {
            return;
        }
        let mut known = remembered(dir);
        known.push(key);
        let hex: Vec<String> = known.iter().map(|k| to_hex(k)).collect();
        if let Ok(text) = serde_json::to_vec_pretty(&serde_json::json!({ "keys": hex })) {
            let _ = write_by_rename(&dir.join(REMEMBERED), &text);
        }
    }
}

/// The remembered keys. A file that does not read is no keys, which fails closed.
fn remembered(dir: &Path) -> Vec<[u8; 32]> {
    let Ok(bytes) = std::fs::read(dir.join(REMEMBERED)) else { return Vec::new() };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else { return Vec::new() };
    let Some(keys) = value.get("keys").and_then(|k| k.as_array()) else { return Vec::new() };
    keys.iter().filter_map(|k| k.as_str().and_then(from_hex::<32>)).collect()
}
