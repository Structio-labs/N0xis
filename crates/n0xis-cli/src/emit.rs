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

/// A refusal with detail the shared failure arm has no field for, as `error.<key>`. Still through here,
/// so there is one place the CLI prints, and still a failure: the exit code says so.
pub fn emit_refusal_with<T: Serialize>(resp: &Response<T>, key: &str, detail: serde_json::Value, pretty: bool) -> bool {
    let mut value = serde_json::to_value(resp).unwrap_or(serde_json::Value::Null);
    if let Some(error) = value.get_mut("error").and_then(serde_json::Value::as_object_mut) {
        error.insert(key.to_string(), detail);
    }
    let text = if pretty { serde_json::to_string_pretty(&value) } else { serde_json::to_string(&value) };
    println!("{}", text.unwrap_or_else(|e| format!("{{\"ok\":false,\"error\":{{\"code\":\"serialize\",\"message\":{e:?}}}}}")));
    false
}
