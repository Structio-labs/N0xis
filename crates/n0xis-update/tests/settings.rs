// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The settings file: its defaults, its refusals, and that it fails towards making no request.

use std::fs;
use std::path::PathBuf;

use n0xis_update::config::{self, Settings};
use n0xis_update::{Why, addresses, MANIFEST_ADDRESSES};
use serde_json::{Value, json};

fn dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("settings-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

#[test]
fn nothing_set_means_the_defaults_of_the_design() {
    let d = dir("defaults");
    assert_eq!(Settings::load(&d).unwrap(), Settings { check: true, auto: false, manifest_url: None });
    let all = config::get(&d, None).unwrap();
    assert_eq!(all["settings"].as_array().unwrap().len(), 3);
    assert_eq!(config::get(&d, Some("update.auto")).unwrap()["settings"][0]["set"], json!(false));
    assert!(!d.exists(), "reading settings wrote something");
}

#[test]
fn a_setting_is_written_read_back_and_cleared() {
    let d = dir("set");
    config::set(&d, "update.check", "false").unwrap();
    config::set(&d, "update.auto", "true").unwrap();
    config::set(&d, "update.manifest_url", "https://mirror.example/manifest.json").unwrap();
    let s = Settings::load(&d).unwrap();
    assert_eq!((s.check, s.auto, s.manifest_url.as_deref()), (false, true, Some("https://mirror.example/manifest.json")));
    config::set(&d, "update.manifest_url", "").unwrap();
    assert_eq!(Settings::load(&d).unwrap().manifest_url, None);
    let names: Vec<_> = fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names, ["config.json"], "a temporary file was left");
}

#[test]
fn what_a_later_build_wrote_is_kept() {
    let d = dir("later");
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join("config.json"), r#"{"gui.theme":"dark","update.check":true}"#).unwrap();
    config::set(&d, "update.auto", "true").unwrap();
    let kept: Value = serde_json::from_slice(&fs::read(d.join("config.json")).unwrap()).unwrap();
    assert_eq!(kept["gui.theme"], json!("dark"));
}

#[test]
fn a_bad_key_or_value_is_refused() {
    let d = dir("bad");
    assert_eq!(config::set(&d, "update.nope", "true").unwrap_err().why, Why::UnknownSetting);
    assert_eq!(config::get(&d, Some("update.nope")).unwrap_err().why, Why::UnknownSetting);
    assert_eq!(config::set(&d, "update.check", "yes").unwrap_err().why, Why::BadSettingValue);
    assert_eq!(config::set(&d, "update.manifest_url", "http://mirror.example/m.json").unwrap_err().why, Why::BadSettingValue);
    assert!(!d.exists());
}

/// `update.check` is on by default, so a damaged file read as "nothing set" would start making
/// requests for a user who had turned them off.
#[test]
fn a_damaged_file_is_refused_and_not_overwritten() {
    let d = dir("damaged");
    fs::create_dir_all(&d).unwrap();
    for damage in ["{ not json", "[]", r#"{"update.check":"no"}"#] {
        fs::write(d.join("config.json"), damage).unwrap();
        assert_eq!(Settings::load(&d).unwrap_err().why, Why::ConfigUnreadable, "{damage}");
    }
    fs::write(d.join("config.json"), "{ not json").unwrap();
    assert_eq!(config::set(&d, "update.auto", "true").unwrap_err().why, Why::ConfigUnreadable);
    assert_eq!(fs::read_to_string(d.join("config.json")).unwrap(), "{ not json");
}

#[test]
fn the_override_is_asked_first_and_the_frozen_addresses_keep_their_order() {
    assert_eq!(MANIFEST_ADDRESSES[0], "https://updates.structio.dev/n0xis/manifest.json");
    assert_eq!(MANIFEST_ADDRESSES[1], "https://github.com/Structio-labs/N0xis/releases/latest/download/manifest.json");
    assert_eq!(addresses(None), MANIFEST_ADDRESSES);
    assert_eq!(addresses(Some("https://a/m"))[0], "https://a/m");
    assert_eq!(addresses(Some("https://a/m"))[1..], MANIFEST_ADDRESSES);
}
