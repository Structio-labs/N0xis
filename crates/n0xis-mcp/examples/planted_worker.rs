// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A worker for `n0xis-mcp`'s parent that dies in a way chosen by the test, for
//! `tests/a_session_survives_the_engine.rs`. A real worker cannot be asked to die on
//! the fourth request, or half way through a line. Speaks just enough of the protocol,
//! and logs each line it reads to `$N0X_PLANTED_LOG` with the number of the worker, so
//! a test can see what each one was given.

use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::time::Duration;

use serde_json::{Value, json};

/// Which worker this is, from the lines earlier ones left in the log.
fn number(log: &str) -> usize {
    std::fs::read_to_string(log).unwrap_or_default().lines().filter(|l| l.ends_with(" started")).count()
}

fn answer(out: &mut impl Write, id: &Value, result: Value) {
    let line = json!({ "jsonrpc": "2.0", "id": id, "result": result });
    writeln!(out, "{line}").expect("write");
    out.flush().expect("flush");
}

#[allow(unconditional_recursion, reason = "the real thing, on Windows and elsewhere")]
fn overflow(n: u64) -> u64 {
    let on_the_stack = [n; 256];
    overflow(on_the_stack[(n % 256) as usize] + 1) + on_the_stack[0]
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("sleeper") {
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    let mode = std::env::var("N0X_PLANTED").expect("a mode");
    let path = std::env::var("N0X_PLANTED_LOG").expect("a log");
    let me = number(&path);
    let mut log = OpenOptions::new().create(true).append(true).open(&path).expect("the log");
    writeln!(log, "{me} started").expect("log");
    if mode == "die-at-start" {
        std::process::exit(5);
    }
    let mut out = std::io::stdout().lock();
    let mut calls = 0;
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("a line");
        writeln!(log, "{me} {line}").expect("log");
        let message: Value = serde_json::from_str(&line).expect("JSON");
        let id = &message["id"];
        match message["method"].as_str() {
            Some("initialize") => {
                if mode == "no-second-initialize" && me > 0 {
                    std::process::exit(6);
                }
                answer(&mut out, id, json!({ "worker": me }));
            }
            Some("tools/call") => {
                calls += 1;
                match (mode.as_str(), calls) {
                    ("past-the-ceiling", _) => std::process::exit(n0xis_mcp::supervisor::EXIT_PAST_THE_CEILING),
                    ("abort", _) => std::process::abort(),
                    ("exit-zero", _) => std::process::exit(0),
                    ("stack-overflow", _) => {
                        let n = overflow(calls);
                        answer(&mut out, id, json!(n));
                    }
                    ("second-call-dies" | "no-second-initialize", 2) => std::process::abort(),
                    ("second-call-dies", 1) => {}
                    ("every-second-call-dies", n) if n % 2 == 0 => std::process::abort(),
                    ("mid-line", _) => {
                        write!(out, "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"text\":\"half of it").expect("write");
                        out.flush().expect("flush");
                        std::process::abort();
                    }
                    ("leaves-its-output-held", _) => {
                        // A process it started has the same standard output, and outlives it.
                        let program = std::env::current_exe().expect("this program");
                        std::mem::forget(std::process::Command::new(program).arg("sleeper").stdin(std::process::Stdio::null()).spawn().expect("the sleeper"));
                        std::process::abort();
                    }
                    ("huge", _) => {
                        let row = vec![b'x'; 1 << 20];
                        write!(out, "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":\"").expect("write");
                        for _ in 0..256 {
                            out.write_all(&row).expect("write");
                        }
                        writeln!(out, "\"}}").expect("write");
                        out.flush().expect("flush");
                    }
                    _ => answer(&mut out, id, json!({ "worker": me, "call": calls })),
                }
            }
            _ => {}
        }
    }
    if mode == "stays-after-end-of-file" {
        std::thread::sleep(Duration::from_secs(120));
    }
}
