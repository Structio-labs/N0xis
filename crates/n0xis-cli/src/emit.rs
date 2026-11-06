// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Stdout emission of the response envelope. The one place the CLI serializes.
//!
//! An answer is written as it serializes, through a buffer: it never exists twice, once
//! as what it is and once as its text. At millions of rows the text alone is hundreds
//! of megabytes.

use std::io::{BufWriter, StdoutLock, Write};

use n0xis_contracts::Response;
use serde::Serialize;

/// How much of an answer waits to be written.
const BUFFER: usize = 64 << 10;

/// Standard output, and whether any of the answer has gone to it. Past that point
/// nothing can be taken back.
struct Written<'a> {
    out: StdoutLock<'a>,
    any: bool,
}

impl Write for Written<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.any = true;
        self.out.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

/// `value` and its line end, on standard output. Whether all of it went: a failure to
/// serialize is the other case. A closed pipe panics, with the message and exit code
/// `println!` has always given it.
fn write_out<T: Serialize>(value: &T, pretty: bool) -> bool {
    let mut out = BufWriter::with_capacity(BUFFER, Written { out: std::io::stdout().lock(), any: false });
    let written = if pretty { serde_json::to_writer_pretty(&mut out, value) } else { serde_json::to_writer(&mut out, value) };
    let written = written.and_then(|()| out.write_all(b"\n").and_then(|()| out.flush()).map_err(serde_json::Error::io));
    match written {
        Ok(()) => true,
        Err(e) if e.is_io() => panic!("failed printing to stdout: {e}"),
        Err(e) => {
            if out.get_ref().any {
                // What has gone cannot be taken back, and a refusal never follows part of
                // an answer. The exit code and this are all that can be said.
                eprintln!("n0xis: the answer could not be serialized past the part written: {e}");
            } else {
                // Nothing has left, so what waits is dropped and this is the whole answer.
                let (mut nothing_written, _) = out.into_parts();
                // Built, not spelled by hand: this was a `{e:?}` in a format string once, which
                // is no JSON string, so the one answer about broken JSON was broken JSON.
                let refusal = Response::<serde_json::Value>::error("serialize", e.to_string());
                let refusal = serde_json::to_string(&refusal).expect("a refusal is strings") + "\n";
                if let Err(e) = nothing_written.write_all(refusal.as_bytes()).and_then(|()| nothing_written.flush()) {
                    panic!("failed printing to stdout: {e}");
                }
            }
            false
        }
    }
}

/// Serialize `resp` to stdout as JSON. Returns whether it was a success arm, so
/// `main` can drive the process exit code. `pretty` toggles indentation.
pub fn emit<T: Serialize>(resp: &Response<T>, pretty: bool) -> bool {
    // The answer is built, so the ceiling has done its work: see `lift_while_writing`.
    let _writing = n0xis_core::lift_while_writing();
    write_out(resp, pretty) && resp.is_ok()
}

/// The ceiling's own refusal, from inside its allocation. The ceiling is gone already,
/// and [`emit`] would wait for this very refusal to end the process.
pub fn write_refusal_past_the_ceiling<T: Serialize>(resp: &Response<T>, pretty: bool) {
    write_out(resp, pretty);
}

/// A refusal with detail the shared failure arm has no field for, as `error.<key>`. Still through here,
/// so there is one place the CLI prints, and still a failure: the exit code says so.
pub fn emit_refusal_with<T: Serialize>(resp: &Response<T>, key: &str, detail: serde_json::Value, pretty: bool) -> bool {
    let mut value = serde_json::to_value(resp).unwrap_or(serde_json::Value::Null);
    if let Some(error) = value.get_mut("error").and_then(serde_json::Value::as_object_mut) {
        error.insert(key.to_string(), detail);
    }
    let _writing = n0xis_core::lift_while_writing();
    write_out(&value, pretty);
    false
}
