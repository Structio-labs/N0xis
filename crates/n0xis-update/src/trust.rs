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
    /// How many of `keys`, from the start, were given and not proved: where a chain's walk starts.
    roots: usize,
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
        let Some(root) = from_hex::<32>(constant) else { return Trust { keys: Vec::new(), roots: 0 } };
        let chain = config_dir.and_then(|dir| read_chain(dir).ok()).unwrap_or_default().chain;
        let keys = walk(vec![root], chain.into_iter().take(CHAIN_MAX_LINKS)).0;
        Trust { keys, roots: 1 }
    }

    /// Exactly these keys.
    pub fn of_keys(keys: &[[u8; 32]]) -> Trust {
        Trust { keys: keys.to_vec(), roots: keys.len() }
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
    ///
    /// Only what verifies is written back, so junk cannot crowd out a real key, as 32 planted records
    /// once did, and a file past its bound is cleaned rather than kept. A file that cannot be read may
    /// hold real records, so then nothing is written.
    pub fn remember(&self, config_dir: Option<&Path>, manifest: &[u8], signature_file: &[u8], key: [u8; 32]) {
        let Some(dir) = config_dir else { return };
        if self.keys.contains(&key) {
            return;
        }
        let Ok(written) = read_chain(dir) else { return };
        let mut chain = walk(self.keys[..self.roots].to_vec(), written.chain.into_iter()).1;
        let manifest = to_hex(manifest);
        if chain.len() >= CHAIN_MAX_LINKS || chain.iter().any(|link| link.manifest == manifest) {
            return;
        }
        chain.push(Link { manifest, signature: String::from_utf8_lossy(signature_file).into_owned() });
        if let Ok(text) = serde_json::to_vec_pretty(&Chain { chain })
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

/// From `keys`, in order: the keys these links prove, and the links that proved one.
fn walk(mut keys: Vec<[u8; 32]>, links: impl Iterator<Item = Link>) -> (Vec<[u8; 32]>, Vec<Link>) {
    let mut proving = Vec::new();
    for link in links {
        if let Some(key) = key_proved_by(&link, &keys) {
            keys.push(key);
            proving.push(link);
        }
    }
    (keys, proving)
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

/// The chain as written: none where there is no file, or one past the bound or not in this form, which
/// fails closed. A read that fails is an error, since the file may hold what cannot be seen just now.
fn read_chain(dir: &Path) -> std::io::Result<Chain> {
    let mut bytes = Vec::new();
    let file = match std::fs::File::open(dir.join(REMEMBERED)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Chain::default()),
        Err(e) => return Err(e),
    };
    file.take(CHAIN_MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > CHAIN_MAX_BYTES {
        return Ok(Chain::default());
    }
    Ok(serde_json::from_slice(&bytes).unwrap_or_default())
}
