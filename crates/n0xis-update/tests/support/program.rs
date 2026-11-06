// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A file the update path can really execute, whatever the platform. It answers as the last line of its
//! own file tells it to, so a test makes a program of any version by appending to this one, and each
//! has its own digest: a version to print, or `hang`, or `fail` and a version to print before exiting 3.

fn main() {
    let me = std::env::current_exe().and_then(std::fs::read).expect("reads itself");
    let start = me.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    match &me[start..] {
        b"hang" => std::thread::sleep(std::time::Duration::from_secs(30)),
        says => match says.strip_prefix(b"fail ") {
            Some(version) => {
                println!("program {}", String::from_utf8_lossy(version));
                std::process::exit(3);
            }
            None => println!("program {}", String::from_utf8_lossy(says)),
        },
    }
}
