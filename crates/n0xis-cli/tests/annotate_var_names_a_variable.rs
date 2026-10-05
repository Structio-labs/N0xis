// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **`annotate var` and `annotate vartype` write only what can take effect.**
//!
//! They stored a rename or a type under any name and answered `ok`: a name that
//! is not a variable of the function, or a type on a value the decompiler never
//! types, changed nothing while reading as done. With an image to decompile
//! (`--file`, or the one a `serve` session holds), the name is now checked
//! against the decompiler's own variable list; without one the answer says it
//! was not checked.
//!
//! The fixture is this test binary's own executable; the project is a temp
//! folder with its own `.n0x/`.

use std::process::Command;

use serde_json::Value;

fn n0xis_exe() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("test exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(if cfg!(windows) { "n0xis.exe" } else { "n0xis" })
}

fn run(cwd: &std::path::Path, args: &[&str]) -> Value {
    let out = Command::new(n0xis_exe()).current_dir(cwd).args(args).arg("--quiet").output().expect("run n0xis");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("one envelope ({e}): {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn only_a_listed_variable_takes_a_name_and_only_a_param_or_local_a_type() {
    if !n0xis_exe().exists() {
        return; // binary not built in this profile
    }
    let project = std::env::temp_dir().join(format!("n0xis-annotate-var-{}", std::process::id()));
    std::fs::create_dir_all(project.join(".n0x")).expect("temp project");
    let fixture = std::env::current_exe().expect("test exe");
    let file = fixture.to_str().expect("utf-8 path");

    // A function whose page shows a parameter and a value that is neither.
    let list = run(&project, &["function", "discover", "--file", file, "--limit", "200"]);
    let (addr, vars) = list["data"]["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .filter_map(|f| f["va"].as_str())
        .find_map(|va| {
            let d = run(&project, &["decomp", "pseudo", "--file", file, "--addr", va]);
            let vars = d["data"]["variables"].as_array()?.clone();
            let has = |kind: &str| vars.iter().any(|v| v["kind"] == kind);
            (has("param") && has("value")).then(|| (va.to_string(), vars))
        })
        .expect("a function with a parameter and a value among the first 200");
    let key_of = |kind: &str| vars.iter().find(|v| v["kind"] == kind).and_then(|v| v["key"].as_str()).unwrap().to_string();
    let (param, value) = (key_of("param"), key_of("value"));

    let refused = run(&project, &["annotate", "var", "--file", file, "--addr", &addr, "--var", "no_such_variable", "--value", "x"]);
    assert_eq!(refused["error"]["code"], "not-a-variable", "{refused}");

    let renamed = run(&project, &["annotate", "var", "--file", file, "--addr", &addr, "--var", &param, "--value", "planted"]);
    assert_eq!(renamed["data"]["var_names"][&param], "planted", "{renamed}");
    // The name the page now shows is taken for the variable it is shown for.
    let again = run(&project, &["annotate", "var", "--file", file, "--addr", &addr, "--var", "planted", "--value", "planted2"]);
    assert_eq!(again["data"]["var_names"][&param], "planted2", "{again}");
    assert!(again["data"]["var_names"].get("planted").is_none(), "nothing stored under the shown name: {again}");

    let typed_value = run(&project, &["annotate", "vartype", "--file", file, "--addr", &addr, "--var", &value, "--value", "int"]);
    assert_eq!(typed_value["error"]["code"], "takes-no-type", "{typed_value}");
    let typed_param = run(&project, &["annotate", "vartype", "--file", file, "--addr", &addr, "--var", &param, "--value", "int"]);
    assert_eq!(typed_param["ok"], true, "{typed_param}");

    // With no image, nothing is checked, and the answer says so.
    let unchecked = run(&project, &["annotate", "var", "--addr", &addr, "--var", "anything", "--value", "x"]);
    assert_eq!(unchecked["ok"], true);
    assert!(unchecked["meta"]["note"].as_str().is_some_and(|n| n.contains("not checked")), "{unchecked}");
    let _ = std::fs::remove_dir_all(&project);
}
