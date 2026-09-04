// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Stdout emission of the response envelope. The one place the CLI serializes.

use n0xis_contracts::Response;
use serde::Serialize;

/// Serialize `resp` to stdout as JSON. Returns whether it was a success arm, so
/// `main` can drive the process exit code. `pretty` toggles indentation.
pub fn emit<T: Serialize>(resp: &Response<T>, pretty: bool) -> bool {
    let text = if pretty {
        serde_json::to_string_pretty(resp)
    } else {
        serde_json::to_string(resp)
    }
    .unwrap_or_else(|e| format!("{{\"ok\":false,\"error\":{{\"code\":\"serialize\",\"message\":{e:?}}}}}"));
    println!("{text}");
    resp.is_ok()
}
