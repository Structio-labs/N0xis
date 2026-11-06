// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The manifest, as much of it as this client reads.
//!
//! ```json
//! { "version": "0.3.8",
//!   "next_key": "<64 hex digits, optional>",
//!   "components": {
//!     "n0xis":     { "linux-x86_64": { "url": "https://…", "size": 13000000, "sha256": "<64 hex>", "file": "n0xis" } },
//!     "n0xis-mcp": { "linux-x86_64": { "url": "https://…", "size": 13000000, "sha256": "<64 hex>", "file": "n0xis-mcp" } } } }
//! ```
//!
//! **This shape is frozen in every copy shipped, so it is read lazily.** The document is parsed down
//! to the version and to untyped components, and an entry is decoded only when this client is about to use
//! it. A later component of another shape, which this client would never touch, cannot make the
//! whole document unreadable, and neither can a `next_key` it does not understand.

use std::collections::BTreeMap;

use semver::Version;
use serde_json::Value;

use crate::{Refusal, Why, from_hex};

/// The key a manifest lists this build's files under, e.g. `linux-x86_64`.
pub fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

#[derive(Debug)]
pub struct Manifest {
    pub version: Version,
    pub next_key: Option<[u8; 32]>,
    components: BTreeMap<String, Value>,
}

/// One file of one component, for one platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub url: String,
    pub size: u64,
    pub sha256: [u8; 32],
    /// The name this file has when installed, for a component other than the running one.
    pub file: Option<String>,
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Manifest, Refusal> {
        let bad = |what: String| Refusal::new(Why::BadManifest, what);
        let value: Value = serde_json::from_slice(bytes).map_err(|e| bad(format!("the manifest does not parse: {e}")))?;
        let version = value.get("version").and_then(Value::as_str).ok_or_else(|| bad("the manifest states no version".to_string()))?;
        let version = Version::parse(version).map_err(|e| bad(format!("the manifest's version {version:?}: {e}")))?;
        let components = match value.get("components") {
            Some(Value::Object(map)) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            _ => return Err(bad("the manifest lists no components".to_string())),
        };
        let next_key = value.get("next_key").and_then(Value::as_str).and_then(from_hex::<32>);
        Ok(Manifest { version, next_key, components })
    }

    /// The entry of `component` for `platform`, or why it cannot be used.
    pub fn entry(&self, component: &str, platform: &str) -> Result<Entry, Refusal> {
        let raw = self.components.get(component).and_then(|c| c.get(platform)).ok_or_else(|| {
            Refusal::new(Why::NoEntry, format!("version {} has no {component} for {platform}", self.version))
        })?;
        Entry::decode(component, raw)
    }

    /// Every other component that lists a file for `platform`, with the name it is installed under.
    ///
    /// A component with no `file` is skipped: it is something later than this client, which installs
    /// only over what is already beside it and never adds what it was not asked for.
    pub fn others<'a>(&'a self, own: &'a str, platform: &'a str) -> impl Iterator<Item = (&'a str, &'a Value, &'a str)> {
        self.components.iter().filter(move |(name, _)| name.as_str() != own).filter_map(move |(name, c)| {
            let raw = c.get(platform)?;
            let file = raw.get("file")?.as_str()?;
            Some((name.as_str(), raw, file))
        })
    }
}

impl Entry {
    /// A missing digest is a refusal of its own, so that no check having been possible never reads
    /// like one having failed, let alone passed.
    pub fn decode(component: &str, raw: &Value) -> Result<Entry, Refusal> {
        let bad = |what: &str| Refusal::new(Why::BadManifest, format!("{component}: {what}"));
        let sha256 = match raw.get("sha256") {
            None | Some(Value::Null) => return Err(Refusal::new(Why::NoDigest, format!("{component}: the manifest gives no digest, so the file cannot be checked"))),
            Some(v) => v.as_str().and_then(from_hex::<32>).ok_or_else(|| Refusal::new(Why::NoDigest, format!("{component}: the manifest's digest is not a sha256")))?,
        };
        let url = raw.get("url").and_then(Value::as_str).ok_or_else(|| bad("no url"))?.to_string();
        let size = raw.get("size").and_then(Value::as_u64).ok_or_else(|| bad("no size"))?;
        let file = raw.get("file").and_then(Value::as_str).map(str::to_string);
        if let Some(name) = &file
            && !is_bare_file_name(name)
        {
            return Err(bad("the file name is not a bare name"));
        }
        Ok(Entry { url, size, sha256, file })
    }
}

/// A name that stays in the directory it is joined to, on every platform.
pub(crate) fn is_bare_file_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', ':'])
}
