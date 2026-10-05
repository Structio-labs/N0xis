// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Paging the function list in a session**: a front end reads a long list a
//! page at a time. Every page used to repeat the whole scan (10.6 s per page of
//! 20 000 on a 159 MB library, whatever the offset), so the scan is now kept for
//! an image that cannot change. Keeping it must not change an answer:
//!
//! - the pages, laid end to end, are the one list an unpaged request returns,
//!   and every page states the same total;
//! - names are attached per page, so a function renamed between two pages
//!   shows its new name on the later one. A kept *named* list would freeze it.
//!
//! The fixture is this test binary's own executable, a real image of the host
//! format. The session runs in a folder with its own `.n0x/`, so the rename
//! stays in that folder.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::Value;

fn n0xis_exe() -> std::path::PathBuf {
    // `target/<profile>/deps/<test>` → `target/<profile>/n0xis`
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

/// Far beyond what these requests take; reached only by a session that has
/// stopped answering.
const SESSION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// One `serve` session in `cwd`; one parsed envelope per line, banner first.
fn serve_in(cwd: &std::path::Path, lines: &[String]) -> Vec<Value> {
    let exe = n0xis_exe();
    if !exe.exists() {
        eprintln!("skipping: {} not built", exe.display());
        return Vec::new();
    }
    let fixture = std::env::current_exe().expect("test exe");
    let mut child = Command::new(&exe)
        .current_dir(cwd)
        .args(["serve", "--quiet", "--file"])
        .arg(&fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for l in lines {
            writeln!(stdin, "{l}").expect("write line");
        }
        writeln!(stdin).expect("blank line ends the session");
    }
    let out = BufReader::new(child.stdout.take().expect("stdout"));
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(out.lines().map_while(Result::ok).collect::<Vec<String>>());
    });
    let raw = match rx.recv_timeout(SESSION_DEADLINE) {
        Ok(raw) => raw,
        Err(_) => {
            let _ = child.kill();
            rx.recv().unwrap_or_default()
        }
    };
    let _ = child.wait();
    raw.iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("every session line is one JSON envelope: {e} in {l}")))
        .collect()
}

fn functions(answer: &Value) -> Vec<(String, String)> {
    answer["data"]["functions"]
        .as_array()
        .unwrap_or_else(|| panic!("a function list: {answer}"))
        .iter()
        .map(|f| (f["va"].as_str().unwrap_or_default().to_string(), f["name"].as_str().unwrap_or_default().to_string()))
        .collect()
}

#[test]
fn pages_laid_end_to_end_are_the_one_list_and_names_stay_current() {
    let project = std::env::temp_dir().join(format!("n0xis-pages-{}", std::process::id()));
    std::fs::create_dir_all(project.join(".n0x")).expect("temp project");

    // First the whole list, to know how to page it and what to rename.
    let whole = serve_in(&project, &["function discover --limit 0".to_string()]);
    if whole.is_empty() {
        return; // binary not built in this profile
    }
    let all = functions(&whole[1]);
    const PAGE: usize = 50;
    assert!(all.len() > PAGE * 2, "the fixture has enough functions to page: {}", all.len());
    let renamed_ix = PAGE + 7;
    let renamed_va = all[renamed_ix].0.clone();

    // Then a session that pages through it, with a rename between pages.
    let pages = all.len().div_ceil(PAGE);
    let mut lines = vec![format!("function discover --limit {PAGE} --offset 0")];
    lines.push(format!("annotate name --addr {renamed_va} --value planted_name"));
    lines.extend((1..pages).map(|n| format!("function discover --limit {PAGE} --offset {}", n * PAGE)));
    let out = serve_in(&project, &lines);
    let _ = std::fs::remove_dir_all(&project);

    let answers: Vec<&Value> = out[1..].iter().filter(|a| a["meta"]["schema"] == "n0xis.function.discover.v1").collect();
    assert_eq!(answers.len(), pages, "one answer per page");
    let mut laid = Vec::new();
    for page in &answers {
        assert_eq!(page["meta"]["total"].as_u64(), Some(all.len() as u64), "every page states the same total: {}", page["meta"]);
        laid.extend(functions(page));
    }
    let addresses = |l: &[(String, String)]| l.iter().map(|(va, _)| va.clone()).collect::<Vec<_>>();
    assert_eq!(addresses(&laid), addresses(&all), "the pages are the one list, in order, nothing twice, nothing missing");
    assert_eq!(laid[renamed_ix].1, "planted_name", "a rename made between pages shows on the later page");
    for (ix, ((_, before), (_, now))) in all.iter().zip(&laid).enumerate() {
        if ix != renamed_ix {
            assert_eq!(before, now, "only the renamed function changed name (#{ix})");
        }
    }
}
