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
    /// How many items `data` actually carries, when the payload is a
    /// capped/paged list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returned: Option<usize>,
    /// How many items existed before the cap, when the command could know it.
    /// Absent means "not counted" — never assume it equals [`Self::returned`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    /// `true` when `data` is a slice of a larger answer. **The whole point of
    /// this field**: without it a reader cannot distinguish "40 results" from
    /// "the first 40 of 277 199", and will draw a conclusion from a fragment
    /// believing it saw everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    /// A directed remark about a result that is easy to misread — most
    /// importantly, an *empty* one that means "wrong tool for this format"
    /// rather than "nothing there". `error.hint` covers failures; this covers
    /// successes that mislead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Meta {
    pub fn new(schema: impl Into<String>) -> Self {
        Meta {
            schema: schema.into(),
            tool: TOOL.to_string(),
            tool_version: tool_version().to_string(),
            source: None,
            elapsed_ms: None,
            returned: None,
            total: None,
            truncated: None,
            note: None,
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

    /// Record that `data` carries `returned` of `total` items — the case where
    /// the command counted everything before slicing (`truncated` is then
    /// derived, never guessed).
    pub fn with_page(mut self, total: usize, returned: usize) -> Self {
        if let Response::Ok(ref mut ok) = self {
            ok.meta.total = Some(total);
            ok.meta.returned = Some(returned);
            ok.meta.truncated = Some(returned < total);
        }
        self
    }

    /// Record that `data` was cut off at `returned` items with the true total
    /// **unknown** — the case where the producer stops early on purpose (an
    /// early-exit scan) and counting the rest would cost the very work the cap
    /// was there to avoid. Reports `truncated` without inventing a `total`.
    pub fn with_cap(mut self, returned: usize) -> Self {
        if let Response::Ok(ref mut ok) = self {
            ok.meta.returned = Some(returned);
            ok.meta.truncated = Some(true);
        }
        self
    }

    /// Attach a note to a *successful* response (no-op on failure). Use it when
    /// the payload is technically correct but reads as something it is not.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        if let Response::Ok(ref mut ok) = self {
            ok.meta.note = Some(note.into());
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
    fn with_page_derives_truncated_both_ways() {
        let full = Response::success("n0xis.demo.v1", serde_json::json!([])).with_page(10, 10);
        let v = serde_json::to_value(&full).unwrap();
        assert_eq!(v["meta"]["truncated"], false, "a complete page is not truncated");
        assert_eq!(v["meta"]["total"], 10);

        let slice = Response::success("n0xis.demo.v1", serde_json::json!([])).with_page(277_199, 40);
        let v = serde_json::to_value(&slice).unwrap();
        assert_eq!(v["meta"]["truncated"], true);
        assert_eq!(v["meta"]["returned"], 40);
        assert_eq!(v["meta"]["total"], 277_199);
    }

    #[test]
    fn with_cap_reports_truncation_without_inventing_a_total() {
        let r = Response::success("n0xis.demo.v1", serde_json::json!([])).with_cap(20);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["meta"]["truncated"], true);
        assert_eq!(v["meta"]["returned"], 20);
        assert!(v["meta"].get("total").is_none(), "an unknown total must stay absent, not be faked");
    }

    #[test]
    fn untruncated_responses_carry_no_paging_noise() {
        let r = Response::success("n0xis.demo.v1", serde_json::json!({"n": 1}));
        let v = serde_json::to_value(&r).unwrap();
        for k in ["returned", "total", "truncated", "note"] {
            assert!(v["meta"].get(k).is_none(), "{k} must be omitted when unset");
        }
    }

    #[test]
    fn a_note_rides_on_success_where_a_hint_cannot() {
        let r = Response::success("n0xis.demo.v1", serde_json::json!({"count": 0}))
            .with_note("zero hits; target looks like IL2CPP");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["ok"], true);
        assert!(v["meta"]["note"].as_str().unwrap().contains("IL2CPP"));
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
