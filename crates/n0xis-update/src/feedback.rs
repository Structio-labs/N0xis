// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `n0x feedback --send`: where to, from the signed manifest; a nonce from the receiver; the work;
//! the post. Only ever because a person ran the command with `--send`: nothing here is reached by
//! the daily check, the MCP server or `serve`.
//!
//! The address is the manifest's, never one this client makes up (docs/design/UPDATE.md §2: the client
//! asks, it never derives), so the receiver can move without a copy in the field being stranded, and
//! a manifest that publishes none is told apart from one that cannot be had.

use serde::Serialize;

use crate::{Refusal, Updater, Why};

/// A report the receiver stored.
#[derive(Clone, Debug, Serialize)]
pub struct Sent {
    /// The receiver's name for it: what to give when asking for its deletion.
    pub id: String,
    /// Where it was posted.
    pub endpoint: String,
}

impl Updater {
    /// Send `built` where the highest manifest that verifies says feedback goes.
    ///
    /// Takes the report as `n0xis-feedback` built it and not bytes, so what is posted is the one
    /// serialization the door showed: there is no second one to differ from it.
    pub fn send_feedback(&self, built: &n0xis_feedback::Built) -> Result<Sent, Refusal> {
        let found = self.fetch_manifest()?;
        let endpoint = found.manifest.feedback()?.ok_or_else(|| {
            Refusal::new(Why::NoFeedbackEndpoint, format!("the manifest of version {} at {} publishes no feedback address", found.manifest.version, found.address))
        })?;
        let challenge = self.transport.get_challenge(&endpoint.challenge)?;
        let unavailable = |what: &str| Refusal::new(Why::FeedbackUnavailable, format!("{}: {what}", endpoint.challenge));
        if challenge.schema != n0xis_feedback::SCHEMA {
            return Err(unavailable(&format!("a challenge of schema {}, and this client speaks {}", challenge.schema, n0xis_feedback::SCHEMA)));
        }
        let nonce = n0xis_feedback::nonce_from_hex(&challenge.nonce).ok_or_else(|| unavailable("the nonce is not 32 bytes of hex"))?;
        let proof = n0xis_feedback::solve(&nonce, built.body(), challenge.difficulty).ok_or_else(|| {
            Refusal::new(
                Why::FeedbackTooHard,
                format!("{} asks for {} bits of work, more than the {} a client does", endpoint.challenge, challenge.difficulty, n0xis_feedback::MAX_DIFFICULTY),
            )
        })?;
        let accepted = self.transport.post_report(&endpoint.report, &challenge.nonce, proof, built.body())?;
        Ok(Sent { id: accepted.id, endpoint: endpoint.report })
    }
}
