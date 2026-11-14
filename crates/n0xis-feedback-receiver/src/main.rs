// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `n0xis-feedback-receiver serve | export | delete`, each from one configuration file.
//!
//! `export` and `delete` are what the owner's machine runs over SSH, under a forced command: one
//! lists the whole reports with their digests, one JSON line each, and the other removes one only
//! when given the digest `export` stated, so a report is removed only once a copy that matches it
//! has been taken.
//!
//! `receiver.example.json` beside this crate is a whole configuration to start from. Its numbers are an
//! example and the deployment's to choose: 64 KiB of text and 10 MiB an attachment are the client's own
//! bounds, so a receiver above them takes nothing more, and `max_body_bytes` is the length prefix, a
//! report's JSON with its text escaped at worst six bytes a byte, and `max_attachments` attachments.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use n0xis_feedback_receiver::{Config, NotDeleted, Receiver};

#[derive(Parser)]
#[command(version, about = "The n0xis feedback receiver")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Listen on the configured loopback address.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// List every whole report in the spool with its digest, one JSON line each.
    Export {
        #[arg(long)]
        config: PathBuf,
    },
    /// Remove one report, only if DIGEST is the one `export` states for it.
    Delete {
        #[arg(long)]
        config: PathBuf,
        /// `YYYY-MM/ID`, as `export` names it.
        report: String,
        digest: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = |path: &PathBuf| Config::load(path).map_err(|e| eprintln!("n0xis-feedback-receiver: {e}"));
    match cli.command {
        Command::Serve { config: path } => {
            let Ok(config) = config(&path) else { return ExitCode::FAILURE };
            let listen = config.listen;
            let receiver = match Receiver::new(config) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("n0xis-feedback-receiver: the spool: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let server = match tiny_http::Server::http(listen) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("n0xis-feedback-receiver: listening on {listen}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            eprintln!("n0xis-feedback-receiver: listening on {listen}");
            n0xis_feedback_receiver::serve(receiver, &server);
            ExitCode::FAILURE
        }
        Command::Export { config: path } => {
            let Ok(config) = config(&path) else { return ExitCode::FAILURE };
            match n0xis_feedback_receiver::export(&config.spool) {
                Ok(ready) => {
                    for r in ready {
                        println!("{}", serde_json::to_string(&r).unwrap_or_default());
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("n0xis-feedback-receiver: reading the spool: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Delete { config: path, report, digest } => {
            let Ok(config) = config(&path) else { return ExitCode::FAILURE };
            match n0xis_feedback_receiver::delete(&config.spool, &report, &digest) {
                Ok(()) => ExitCode::SUCCESS,
                Err(why) => {
                    let said = match why {
                        NotDeleted::NotAReport => "not a report name of the form YYYY-MM/ID".to_string(),
                        NotDeleted::NoSuchReport => "no such report".to_string(),
                        NotDeleted::DigestDiffers => "the digest is not this report's; nothing was removed".to_string(),
                        NotDeleted::Io(e) => e,
                    };
                    eprintln!("n0xis-feedback-receiver: {report}: {said}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
