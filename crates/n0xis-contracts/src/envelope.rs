//! The universal output envelope: every command / MCP tool returns either
//! `{ ok: true, data, meta }` or `{ ok: false, error }`. This is the stable
//! contract agents parse; it is defined **once**, here.

use serde::{Deserialize, Serialize};

use crate::{TOOL, tool_version};

/// Metadata attached to every successful response. `schema` identifies the
/// shape of `data` (see [`crate::schema`]); the rest is provenance an agent can
/// trust across runs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Meta {
    /// Schema id of the `data` payload, e.g. `"n0xis.decode.v1"`.
    pub schema: String,
    /// Always `"n0xis"`.
    pub tool: String,
    /// Version of the contracts crate.
    pub tool_version: String,
    /// What produced the bytes: `"snapshot:test"`, `"static:game.exe"`,
    /// `"live:1234"`. Absent when not applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Wall-clock cost of the operation, when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

impl Meta {
    pub fn new(schema: impl Into<String>) -> Self {
        Meta {
            schema: schema.into(),
            tool: TOOL.to_string(),
            tool_version: tool_version().to_string(),
            source: None,
            elapsed_ms: None,
        }
    }
}

/// The error payload of a failed response. `code` is a stable machine token
/// (kebab or snake); `message` is human/agent-readable; `hint` optionally
/// suggests a fix.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// The success arm: `{ ok: true, data, meta }`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Success<T> {
    pub ok: bool,
    pub data: T,
    pub meta: Meta,
}

/// The failure arm: `{ ok: false, error }`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Failure {
    pub ok: bool,
    pub error: ErrorBody,
}

/// The response union. Serializes untagged to exactly one of the two arms —
/// the `ok` boolean is the discriminator a reader keys on.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Response<T> {
    Ok(Success<T>),
    Err(Failure),
}

impl<T> Response<T> {
    /// Build a success response tagged with `schema`.
    pub fn success(schema: impl Into<String>, data: T) -> Self {
        Response::Ok(Success {
            ok: true,
            data,
            meta: Meta::new(schema),
        })
    }

    /// Build a failure response. Works for any `T` (the failure arm carries no
    /// payload), so error paths need not name a data type.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Response::Err(Failure {
            ok: false,
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
                hint: None,
            },
        })
    }

    /// Attach a `hint` to a failure response (no-op on success).
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        if let Response::Err(ref mut f) = self {
            f.error.hint = Some(hint.into());
        }
        self
    }

    /// Record where the analyzed bytes came from (no-op on failure).
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        if let Response::Ok(ref mut ok) = self {
            ok.meta.source = Some(source.into());
        }
        self
    }

    /// Record how long the operation took (no-op on failure).
    pub fn with_elapsed_ms(mut self, ms: u64) -> Self {
        if let Response::Ok(ref mut ok) = self {
            ok.meta.elapsed_ms = Some(ms);
        }
        self
    }

    /// `true` for the success arm — a convenient exit-code driver for the CLI.
    pub fn is_ok(&self) -> bool {
        matches!(self, Response::Ok(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_shape() {
        let r = Response::success("n0xis.demo.v1", serde_json::json!({"n": 1}))
            .with_source("snapshot:test");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["n"], 1);
        assert_eq!(v["meta"]["schema"], "n0xis.demo.v1");
        assert_eq!(v["meta"]["tool"], "n0xis");
        assert_eq!(v["meta"]["source"], "snapshot:test");
    }

    #[test]
    fn failure_shape() {
        let r: Response<serde_json::Value> =
            Response::error("bad-addr", "not mapped").with_hint("attach first");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "bad-addr");
        assert_eq!(v["error"]["hint"], "attach first");
        assert!(v.get("data").is_none());
    }
}
