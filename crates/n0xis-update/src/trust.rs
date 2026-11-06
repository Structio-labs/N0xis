// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Which keys may sign a manifest, and the check.

use std::io::Read;
use std::path::Path;

use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::{Manifest, Refusal, Why, from_hex, to_hex, write_by_rename};

/// The release's ed25519 public key, 64 hex digits; the private key never leaves the owner's machine.
///
/// **This placeholder is not hex, on purpose: a build that still holds it refuses every manifest.**
/// All zeros would parse, and a key of small order is one a signature can be forged against, so a
/// placeholder that looks like a key would be a hole rather than a refusal. `scripts/release.py`
/// refuses to publish while this holds it, or a key that is not the signing key's.
pub const RELEASE_PUBLIC_KEY: &str = "PLACEHOLDER: the release public key goes here, and until then every manifest is refused";

/// Where a change of key is remembered, in the user's configuration directory: the signed statements
/// themselves, and not the keys they name, so that writing this file grants nothing.
const REMEMBERED: &str = "update-keys.json";
/// Past either bound the file is not one this client wrote. A chain is one link per change of key.
const CHAIN_MAX_BYTES: u64 = 1024 * 1024;
const CHAIN_MAX_LINKS: usize = 32;

#[derive(Default, Serialize, Deserialize)]
struct Chain {
    chain: Vec<Link>,
}

/// One signed manifest that named a next key, exactly as it was verified.
#[derive(Serialize, Deserialize)]
struct Link {
    /// Hex of the manifest's exact bytes.
    manifest: String,
    /// The text of its `.sig`.
    signature: String,
}

/// The keys a signature is checked against.
#[derive(Debug)]
pub struct Trust {
    keys: Vec<[u8; 32]>,
}

impl Trust {
    /// The built-in key, and each next key the remembered chain proves from it.
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
        for link in config_dir.map(read_chain).unwrap_or_default().chain.iter().take(CHAIN_MAX_LINKS) {
            if let Some(key) = key_proved_by(link, &keys) {
                keys.push(key);
            }
        }
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
        verify_under(&self.keys, manifest, signature_file)
    }

    /// Keep the manifest that named a next key, with its signature, so a later run can prove the key
    /// from the key before it. A failed write costs only the change of key, which a co-signed release
    /// or a hand download still gets past, so it does not fail the check that found the key; the same
    /// goes for a chain already at its bounds, which no real history reaches.
    pub fn remember(&self, config_dir: Option<&Path>, manifest: &[u8], signature_file: &[u8], key: [u8; 32]) {
        let Some(dir) = config_dir else { return };
        if self.keys.contains(&key) {
            return;
        }
        let mut known = read_chain(dir);
        let manifest = to_hex(manifest);
        if known.chain.len() >= CHAIN_MAX_LINKS || known.chain.iter().any(|link| link.manifest == manifest) {
            return;
        }
        known.chain.push(Link { manifest, signature: String::from_utf8_lossy(signature_file).into_owned() });
        if let Ok(text) = serde_json::to_vec_pretty(&known)
            && text.len() as u64 <= CHAIN_MAX_BYTES
        {
            let _ = write_by_rename(&dir.join(REMEMBERED), &text);
        }
    }
}

fn verify_under(keys: &[[u8; 32]], manifest: &[u8], signature_file: &[u8]) -> Result<(), Refusal> {
    let text = String::from_utf8_lossy(signature_file);
    let signatures: Vec<[u8; 64]> = text.lines().filter_map(|line| from_hex::<64>(line.trim())).collect();
    if signatures.is_empty() {
        return Err(Refusal::new(Why::NoSignature, "the signature file holds no signature"));
    }
    let verifies = |key: &[u8; 32], sig: &[u8; 64]| UnparsedPublicKey::new(&ED25519, key).verify(manifest, sig).is_ok();
    if keys.iter().any(|key| signatures.iter().any(|sig| verifies(key, sig))) {
        return Ok(());
    }
    Err(Refusal::new(Why::BadSignature, "the manifest's signature does not verify under any key this build trusts"))
}

/// The next key this link names, if it verifies under `keys` and names one. Anything else is skipped.
fn key_proved_by(link: &Link, keys: &[[u8; 32]]) -> Option<[u8; 32]> {
    let manifest = hex_bytes(&link.manifest)?;
    verify_under(keys, &manifest, link.signature.as_bytes()).ok()?;
    Manifest::parse(&manifest).ok()?.next_key
}

fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let pairs = text.as_bytes().as_chunks::<2>();
    if !pairs.1.is_empty() {
        return None;
    }
    pairs.0.iter().map(|pair| from_hex::<1>(std::str::from_utf8(pair).ok()?).map(|b| b[0])).collect()
}

/// The chain as written. A file that does not read, or is past the bound, is no chain, which fails closed.
fn read_chain(dir: &Path) -> Chain {
    let mut bytes = Vec::new();
    let read = std::fs::File::open(dir.join(REMEMBERED)).and_then(|file| file.take(CHAIN_MAX_BYTES + 1).read_to_end(&mut bytes));
    if read.is_err() || bytes.len() as u64 > CHAIN_MAX_BYTES {
        return Chain::default();
    }
    serde_json::from_slice(&bytes).unwrap_or_default()
}
