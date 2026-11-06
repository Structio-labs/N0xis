#!/usr/bin/env python3
"""Calibrate the update path's tests: remove what each guards, and the named test must fail.

    python3 scripts/calibrate_update.py            all of them
    python3 scripts/calibrate_update.py -k notice  those whose source file or test name match

A calibration that passes is either a calibrated test or a mutation that missed, and those look
identical from the outside. So each mutation asserts its anchor is there exactly once, the files are
restored from the bytes read (never from git: uncommitted work would go with it), and the run is judged
by the *named* test failing, not by something failing. It edits the work tree while it runs, so
nothing else should build from this tree meanwhile.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPDATE = "crates/n0xis-update/src/"

# What is installed is read under the lock, not before it: the same test, done ahead of the loop.
LOCK_THEN = """            match lock_for_install(&item, asked, &manifest.version) {
                Ok(lock) => locks.push(lock),
                Err(r) if item.runs && r.why == Why::Held => {
                    report.skipped.push(Skipped::of(&item.component, r));
                    return Ok(report);
                }
                Err(r) if item.runs => return Err(r),
                Err(r) => {
                    report.skipped.push(Skipped::of(&item.component, r));
                    continue;
                }
            }
"""
READ_UNDER_THE_LOCK = """        for item in plan {
""" + LOCK_THEN + """            // Already the file named is said first, since moving nothing is true however it got there:
            // a run that waited out another at the lock answers `unchanged`.
            if measure(&item.target).is_ok_and(|(_, sum)| sum == item.entry.sha256) {
"""
READ_BEFORE_THE_LOCK = """        let plan: Vec<_> = plan.into_iter().map(|item| { let same = measure(&item.target).is_ok_and(|(_, sum)| sum == item.entry.sha256); (item, same) }).collect();
        for (item, same) in plan {
""" + LOCK_THEN + """            if same {
"""

# (file, anchor, replacement, package, test binary, test name)
PLANTED = ("n0xis-update", "planted")
SETTINGS = ("n0xis-update", "settings")
DOOR = ("n0xis-cli", "update_door")
MCP = ("n0xis-mcp", "states_its_version_and_a_newer_one")
RELEASE = ("n0xis-update", "release_script")
MUTATIONS = [
    (UPDATE + "net.rs", ".https_only(true)", ".https_only(false)", *PLANTED, "plain_http_is_refused_without_a_connection"),
    (UPDATE + "net.rs", ".https_only(true)", ".https_only(false)", *PLANTED, "a_redirect_to_plain_http_is_refused"),
    (UPDATE + "net.rs", ".https_only(true)", ".https_only(false)", *PLANTED, "a_file_at_a_plain_http_address_is_refused"),
    (UPDATE + "lib.rs", "self.trust.verify(&bytes, &signature)?;", "let _ = &signature;", *PLANTED, "a_bad_signature_is_refused"),
    (UPDATE + "lib.rs", "self.trust.verify(&bytes, &signature)?;", "let _ = &signature;", *PLANTED, "a_manifest_changed_after_signing_is_refused"),
    (UPDATE + "lib.rs", "self.trust.verify(&bytes, &signature)?;", "let _ = &signature;", *PLANTED, "the_placeholder_refuses_every_manifest_whatever_the_key_file_says"),
    (UPDATE + "trust.rs", "if signatures.is_empty() {", "if false {", *PLANTED, "no_signature_is_its_own_refusal"),
    (UPDATE + "lib.rs", "let signature = self.transport.get_signature(&format!(\"{address}{SIGNATURE_SUFFIX}\"))?;", "let signature = self.transport.get_signature(&format!(\"{address}{SIGNATURE_SUFFIX}\")).unwrap_or_else(|_| vec![b'0'; 128]);", *PLANTED, "no_signature_is_its_own_refusal"),
    (UPDATE + "trust.rs", "let Some(root) = from_hex::<32>(constant) else { return Trust { keys: Vec::new(), roots: 0 } };", "let root = from_hex::<32>(constant).unwrap_or([7u8; 32]);", *PLANTED, "the_placeholder_refuses_every_manifest_whatever_the_key_file_says"),
    (UPDATE + "lib.rs", "self.trust.remember(self.config_dir.as_deref(), &bytes, &signature, key);", "let _ = key;", *PLANTED, "a_signed_manifest_can_name_the_next_key"),
    (UPDATE + "trust.rs", "if keys.iter().any(|key| signatures.iter().any(|sig| verifies(key, sig))) {", "if signatures.first().is_some_and(|sig| keys.iter().any(|key| verifies(key, sig))) {", *PLANTED, "either_of_two_signatures_is_enough"),
    (UPDATE + "install.rs", "if sum != item.entry.sha256 {", "if false {", *PLANTED, "a_tampered_file_is_refused"),
    (UPDATE + "install.rs", "if sum != item.entry.sha256 {", "if false {", *PLANTED, "a_wrong_digest_is_refused"),
    (UPDATE + "install.rs", "if sum != item.entry.sha256 {", "if false {", *PLANTED, "a_bad_sibling_file_is_skipped_and_the_running_file_goes_on"),
    (UPDATE + "manifest.rs", 'None | Some(Value::Null) => return Err(Refusal::new(Why::NoDigest, format!("{component}: the manifest gives no digest, so the file cannot be checked"))),', "None | Some(Value::Null) => [0u8; 32],", *PLANTED, "no_digest_is_its_own_refusal_not_a_passed_check"),
    (UPDATE + "install.rs", "if size != item.entry.size {", "if false {", *PLANTED, "a_truncated_download_is_refused"),
    (UPDATE + "install.rs", "if size != item.entry.size {", "if false {", *PLANTED, "a_claimed_size_past_what_is_sent_is_refused"),
    (UPDATE + "net.rs", "Err(e) if got < size && ended_early(&e) => {", "Err(e) if false && ended_early(&e) => {", *PLANTED, "a_truncated_download_is_refused"),
    (UPDATE + "net.rs", "if got > size {", "if false {", *PLANTED, "a_file_that_never_ends_stops_being_read_at_the_limit"),
    (UPDATE + "install.rs", "if manifest.version < self.current {", "if false {", *PLANTED, "an_older_version_is_refused_and_the_same_one_changes_nothing"),
    (UPDATE + "install.rs", "if manifest.version == self.current {", "if false {", *PLANTED, "an_older_version_is_refused_and_the_same_one_changes_nothing"),
    (UPDATE + "lib.rs", "worst = Some(worst.map_or(r.why, |w| w.max(r.why)));", "if self.addresses.len() > 1 { return Err(r); }", *PLANTED, "a_dead_first_address_falls_through_quietly"),
    (UPDATE + "lib.rs", "worst = Some(worst.map_or(r.why, |w| w.max(r.why)));", "if r.why != Why::ManifestUnavailable { return Err(r); }", *PLANTED, "a_first_address_answering_badly_does_not_strand_the_client"),
    (UPDATE + "lib.rs", "worst = Some(worst.map_or(r.why, |w| w.max(r.why)));", "worst = Some(r.why);", *PLANTED, "the_most_serious_failure_is_the_one_reported"),
    (UPDATE + "lib.rs", "available: newer && blocked.is_none(),", "available: newer,", *PLANTED, "no_entry_for_this_platform_is_a_refusal"),
    (UPDATE + "manifest.rs", 'value.get("next_key").and_then(Value::as_str).and_then(from_hex::<32>);', 'Some(value.get("next_key").map_or(Ok(None), |v| v.as_str().map(|s| from_hex::<32>(s)).ok_or_else(|| bad("next_key".to_string())))?).flatten();', *PLANTED, "unknown_fields_and_unknown_components_are_ignored"),
    (UPDATE + "install.rs", "let Some(target) = regular_file(&dir.join(file))? else { return Ok(None) };", "let target = dir.join(file);", *PLANTED, "a_component_not_installed_is_not_added"),
    (UPDATE + "install.rs", "if measure(&item.target).is_ok_and(|(_, sum)| sum == item.entry.sha256) {", "if false {", *PLANTED, "a_component_that_did_not_change_is_not_fetched"),
    (UPDATE + "manifest.rs", '!name.is_empty() && name != "." && name != ".." && !name.contains([\'/\', \'\\\\\', \':\'])', "!name.is_empty()", *PLANTED, "a_file_name_cannot_leave_the_directory"),
    (UPDATE + "install.rs", "let _ = fs::remove_file(&self.0);", "let _ = &self.0;", *PLANTED, "a_tampered_file_is_refused"),
    (UPDATE + "install.rs", "        set_mode(&new_file.0, mode).map_err(disk)?;\n", "", *PLANTED, "a_newer_release_installs_keeps_the_old_file_and_rolls_back"),
    (UPDATE + "install.rs", "|e| not_writable(&item.target, &item.entry, e))?;", "|e| Refusal::new(Why::InstallFailed, e.to_string()))?;", *PLANTED, "a_directory_that_cannot_be_written_is_a_refusal_naming_the_file"),
    (UPDATE + "install.rs", '.with_hint(format!("fetch {} ({} bytes, sha256 {}) and put it at {} yourself", entry.url, entry.size,', '.with_hint(format!("fetch {} ({} bytes, sha256 {}) and put it at {} yourself", "it", entry.size,', *PLANTED, "a_directory_that_cannot_be_written_is_a_refusal_naming_the_file"),
    (UPDATE + "install.rs", "Some(name) if is_bare_file_name(name) => exe.with_file_name(name),", "Some(_) => exe.to_path_buf(),", *PLANTED, "a_component_beside_the_binary_goes_with_it_and_goes_back_by_its_name"),
    (UPDATE + "net.rs", ".timeout_recv_response(Some(limits.response))", ".timeout_recv_response(None)", *PLANTED, "a_silent_server_ends_in_a_refusal_within_the_bound"),
    (UPDATE + "net.rs", ".timeout_recv_body(Some(body))", ".timeout_recv_body(None)", *PLANTED, "a_body_that_stalls_ends_in_a_refusal_within_the_bound"),
    (UPDATE + "net.rs", ".max_redirects(limits.redirects)", ".max_redirects(50)", *PLANTED, "a_redirect_over_https_is_followed_and_a_loop_is_bounded"),
    (UPDATE + "net.rs", ".max_redirects(limits.redirects)", ".max_redirects(1)", *PLANTED, "a_redirect_over_https_is_followed_and_a_loop_is_bounded"),
    (UPDATE + "net.rs", ".with_config().limit(max).read_to_vec()", ".with_config().limit(u64::MAX).read_to_vec()", *PLANTED, "an_endless_manifest_is_not_read_to_its_end"),
    (UPDATE + "install.rs", "if asked == Asked::Auto {", "if false {", *PLANTED, "update_auto_installs_under_the_same_checks_and_rollback_holds_it"),
    (UPDATE + "notice.rs", "if report.available && auto {", "if report.available {", *PLANTED, "the_daily_check_writes_what_it_learned_and_touches_nothing"),
    (UPDATE + "notice.rs", "state.latest = report.available.then(|| report.latest.clone());", "state.latest = Some(report.latest.clone());", *PLANTED, "the_daily_check_writes_what_it_learned_and_touches_nothing"),
    (UPDATE + "config.rs", 'Err(e) => Err(Refusal::new(Why::ConfigUnreadable, format!("{}: {e}", path.display()))),\n    }\n}', 'Err(_) => Ok(Map::new()),\n    }\n}', *SETTINGS, "a_damaged_file_is_refused_and_not_overwritten"),
    (UPDATE + "config.rs", '} else if value.starts_with("https://") {', "} else if true {", *SETTINGS, "a_bad_key_or_value_is_refused"),
    # A. Which manifest.
    (UPDATE + "lib.rs", "if best.as_ref().is_none_or(|(held, _)| manifest.version > held.version) {", "if best.is_none() {", *PLANTED, "a_stale_first_address_does_not_hide_a_newer_second"),
    (UPDATE + "lib.rs", "let manifest = Manifest::parse(&bytes)?;\n        if let Some(key) = manifest.next_key {", "let manifest = Manifest::parse(&bytes)?;\n        if let Some(key) = manifest.next_key.filter(|_| manifest.version.major > 1) {", *PLANTED, "a_next_key_is_remembered_from_a_manifest_that_did_not_win"),
    # B. A chain and not a list.
    (UPDATE + "trust.rs", "verify_under(keys, &manifest, link.signature.as_bytes()).ok()?;\n", "", *PLANTED, "a_planted_key_file_trusts_nothing"),
    (UPDATE + "trust.rs", "verify_under(keys, &manifest, link.signature.as_bytes()).ok()?;\n", "", *PLANTED, "a_two_hop_chain_does"),
    (UPDATE + "trust.rs", "            keys.push(key);\n", "            let _ = key;\n", *PLANTED, "a_two_hop_chain_does"),
    (UPDATE + "trust.rs", "chain.into_iter().take(CHAIN_MAX_LINKS)).0;", "chain.into_iter()).0;", *PLANTED, "a_key_file_past_its_bounds_proves_nothing_past_them"),
    (UPDATE + "trust.rs", "if bytes.len() as u64 > CHAIN_MAX_BYTES {", "if false {", *PLANTED, "a_key_file_past_its_bounds_proves_nothing_past_them"),
    (UPDATE + "lib.rs", ".create_new(true)\n        .open(&temp)", ".create(true)\n        .truncate(true)\n        .open(&temp)", *PLANTED, "a_link_planted_at_a_temporary_name_is_not_followed"),
    # C. A directory that is not yours.
    (UPDATE + "config.rs", "return found.is_dir() && found.uid() == me && found.mode() & 0o002 == 0,", "return found.is_dir() && found.mode() & 0o002 == 0,", *SETTINGS, "a_directory_of_another_owner_is_not_mine"),
    (UPDATE + "config.rs", "return found.is_dir() && found.uid() == me && found.mode() & 0o002 == 0,", "return found.is_dir() && found.uid() == me,", *SETTINGS, "a_directory_of_another_owner_is_not_mine"),
    (UPDATE + "config.rs", "named_dir().filter(|dir| is_mine(dir))", "named_dir()", *DOOR, "a_directory_of_another_owner_does_not_exist"),
    # D. The install.
    (UPDATE + "install.rs", "answers_its_version(&new_file.0, &report.to, self.transport.run_bound)?;", "let _ = answers_its_version;", *PLANTED, "a_garbage_signed_file_is_refused_with_the_target_unchanged"),
    (UPDATE + "install.rs", "if !status.success() {", "if false {", *PLANTED, "a_file_that_answers_wrongly_does_not_run"),
    (UPDATE + "install.rs", "if text.split_whitespace().any(|word| word == version) {", "if text.contains(version) {", *PLANTED, "a_file_that_answers_wrongly_does_not_run"),
    (UPDATE + "install.rs", "Ok(None) if start.elapsed() < bound => std::thread::sleep(Duration::from_millis(20)),", "Ok(None) => std::thread::sleep(Duration::from_millis(20)),\n            #[allow(unreachable_patterns)]", *PLANTED, "a_file_that_never_answers_ends_within_the_bound"),
    (UPDATE + "install.rs", "if from_hex::<32>(&record.previous_sha256) != Some(sum) {", "if false {", *PLANTED, "a_previous_that_does_not_match_is_refused"),
    (UPDATE + "install.rs", "custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)", "custom_flags(libc::O_NONBLOCK)", *PLANTED, "a_planted_previous_symlink_is_refused"),
    (UPDATE + "install.rs", "if installed_hex == record.previous_sha256 {", "if false {", *PLANTED, "a_previous_equal_to_the_target_says_that_nothing_changed"),
    (UPDATE + "install.rs", "let reads = record.from.as_deref().is_none_or(|from| Version::parse(from).is_ok()) && Version::parse(&record.to).is_ok() && from_hex::<32>(&record.previous_sha256).is_some() && from_hex::<32>(&record.installed_sha256).is_some();", "let reads = from_hex::<32>(&record.previous_sha256).is_some();", *PLANTED, "a_record_that_does_not_read_as_versions_is_no_record"),
    (UPDATE + "install.rs", "Err(TryLockError::WouldBlock) => return Err(Refusal::new(Why::UpdateInProgress, format!(\"another run holds {}\", path.display()))),", "Err(TryLockError::WouldBlock) => return Ok(file),", *PLANTED, "a_held_lock_stops_update_rollback_and_the_detached_copy"),
    (UPDATE + "notice.rs", "Err(r) if matches!(r.why, Why::UpdateInProgress | Why::ChangedDuringUpdate) => {}", "Err(r) if matches!(r.why, Why::NoEntry | Why::ChangedDuringUpdate) => {}", *PLANTED, "a_held_lock_stops_update_rollback_and_the_detached_copy"),
    (UPDATE + "install.rs", "Err(TryLockError::WouldBlock) => return Err(Refusal::new(Why::UpdateInProgress, format!(\"another run holds {}\", path.display()))),", "Err(TryLockError::WouldBlock) => return Ok(file),", *PLANTED, "parallel_runs_keep_the_old_file_for_rollback"),
    (UPDATE + "install.rs", "std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);", "std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o666);", *PLANTED, "the_new_file_is_0600_under_umask_000"),
    (UPDATE + "install.rs", "let (size, sum) = measure(&new_file.0).map_err(disk)?;", "let (size, sum) = (item.entry.size, item.entry.sha256);", *PLANTED, "a_file_altered_after_the_download_is_refused"),
    (UPDATE + "install.rs", "Ok(fs::metadata(target)?.permissions().mode() & 0o777)", "Ok(fs::metadata(target)?.permissions().mode() & 0o7777)", *PLANTED, "setuid_is_not_carried_over"),
    (UPDATE + "install.rs", "let real = if found.file_type().is_symlink() {", "let real = if false {", *PLANTED, "a_symlinked_sibling_stays_a_link_and_comes_back_by_its_name"),
    (UPDATE + "install.rs", "if fs::symlink_metadata(&real).is_ok_and(|m| m.is_file()) { Ok(Some(real)) } else { Err(strange(\"is not a regular file\".to_string())) }", "if fs::symlink_metadata(&real).is_ok_and(|m| m.is_file()) { Ok(Some(real)) } else { Ok(None) }", *PLANTED, "a_sibling_that_is_not_a_regular_file_is_skipped"),
    (UPDATE + "install.rs", "    refusal.components = outcomes;\n", "    let _ = outcomes;\n", *PLANTED, "a_commit_failure_reports_each_component"),
    (UPDATE + "install.rs", "for item in &changing {\n            sweep(&item.target);\n        }\n", "", *PLANTED, "what_a_dead_run_left_is_swept_under_the_lock"),
    # E. The small ones, and the push.
    (UPDATE + "install.rs", READ_UNDER_THE_LOCK, READ_BEFORE_THE_LOCK, *PLANTED, "a_run_that_waited_out_another_reads_what_it_left"),
    (UPDATE + "notice.rs", "entries.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect()", "{ let _ = entries; (3..1024).collect() }", *DOOR, "on_a_terminal::the_copy_lets_go_of_a_handle_above_1024"),
    (UPDATE + "notice.rs", "if lock.try_lock().is_err() || !a_day_has_passed(read_stamp(&path), at) {", "let _ = &lock;\n    if !a_day_has_passed(read_stamp(&path), at) {", *DOOR, "on_a_terminal::a_stamp_being_claimed_starts_no_second_check"),
    (UPDATE + "notice.rs", "installed: state.installed.filter(|i| is_version(&i.from) && is_version(&i.to)),", "installed: state.installed,", *DOOR, "on_a_terminal::an_escape_in_the_state_file_never_reaches_the_terminal"),
    ("scripts/release.py", 'run("git", "push", PUSH_TO, f"refs/tags/{tag}", cwd=ROOT)', 'run("git", "push", "origin", tag, cwd=ROOT)', "n0xis-update", "release_script", "publishing_pushes_only_the_tag_to_the_named_address"),
    # F. Rollback is one file.
    (UPDATE + "install.rs", "let _ = fs::remove_file(with_suffix(&target, RECORD));", "let _ = fs::remove_file(with_suffix(&target, RECORD));\n    for e in fs::read_dir(target.parent().unwrap()).unwrap().flatten() {\n        let p = e.path();\n        if p != target && fs::symlink_metadata(with_suffix(&p, PREVIOUS)).is_ok() {\n            let _ = put_in_place(&with_suffix(&p, PREVIOUS), &p);\n        }\n    }", *PLANTED, "rollback_leaves_a_sibling_and_another_copy_alone"),
    (UPDATE + "install.rs", "let _lock = take_lock(&target,", "let _lock = take_lock(exe,", *PLANTED, "rollback_takes_a_bare_name_and_that_files_own_lock"),
    (UPDATE + "install.rs", "Some(name) if is_bare_file_name(name) => exe.with_file_name(name),", "Some(name) if !name.is_empty() => exe.with_file_name(name),", *PLANTED, "rollback_takes_a_bare_name_and_that_files_own_lock"),
    (UPDATE + "install.rs", "match lock_for_install(&item, asked, &manifest.version) {", "match (if item.runs { lock_for_install(&item, asked, &manifest.version) } else { File::open(&item.target).map_err(|e| Refusal::new(Why::InstallFailed, e.to_string())) }) {", *PLANTED, "an_install_skips_a_sibling_whose_own_lock_is_held"),
    ("crates/n0xis-cli/src/main.rs", '.and_then(|exe| n0xis_update::rollback(&exe, name.as_deref()));', '.and_then(|exe| n0xis_update::rollback(&exe, name.as_deref().filter(|_| false)));', *DOOR, "rollback_takes_a_bare_name"),
    # 4. A sibling's version is not known.
    (UPDATE + "install.rs", "from: item.runs.then(|| report.from.clone()),", "from: Some(report.from.clone()),", *PLANTED, "a_siblings_version_is_not_known"),
    (UPDATE + "install.rs", "        None => (None, None),\n", "        None => (Some(record.to), None),\n", *PLANTED, "a_siblings_version_is_not_known"),
    (UPDATE + "install.rs", "record.from.as_deref().is_none_or(|from| Version::parse(from).is_ok())", "record.from.as_deref().is_some_and(|from| Version::parse(from).is_ok())", *PLANTED, "a_siblings_version_is_not_known"),
    (UPDATE + "install.rs", "sha256: record.previous_sha256, nothing_changed: None", "sha256: to_hex(&installed), nothing_changed: None", *PLANTED, "a_siblings_version_is_not_known"),
    # 6. The file changed under us.
    *[(UPDATE + "install.rs", "} else if item.runs && Seen::of(&item.target) != found.before {", "} else if false {", *PLANTED, test) for test in ("a_rollback_landing_during_the_fetch_moves_nothing", "the_detached_copy_skips_a_file_that_changed_in_silence", "another_updater_landing_during_the_fetch_moves_nothing", "each_of_inode_size_and_mtime_is_a_change")],
    (UPDATE + "notice.rs", "Err(r) if matches!(r.why, Why::UpdateInProgress | Why::ChangedDuringUpdate) => {}", "Err(r) if r.why == Why::UpdateInProgress => {}", *PLANTED, "the_detached_copy_skips_a_file_that_changed_in_silence"),
    (UPDATE + "install.rs", "inode: std::os::unix::fs::MetadataExt::ino(&found),", "inode: 0,", *PLANTED, "each_of_inode_size_and_mtime_is_a_change"),
    (UPDATE + "install.rs", "size: found.len(),\n", "size: 0,\n", *PLANTED, "each_of_inode_size_and_mtime_is_a_change"),
    (UPDATE + "install.rs", "modified: found.modified().ok(),", "modified: None,", *PLANTED, "each_of_inode_size_and_mtime_is_a_change"),
    # Taken once and kept, an install by this process is the difference it finds.
    (UPDATE + "lib.rs", "let before = install::Seen::of(&self.exe);", "static FIRST: std::sync::OnceLock<Option<install::Seen>> = std::sync::OnceLock::new();\n        let before = *FIRST.get_or_init(|| install::Seen::of(&self.exe));", *PLANTED, "a_fresh_install_in_this_process_is_not_its_own_trigger"),
    # Said before what is installed is read, a run that waited out another is refused for finding what it wanted.
    (UPDATE + "install.rs", "if measure(&item.target).is_ok_and(|(_, sum)| sum == item.entry.sha256) {\n                report.unchanged.push(item.component);\n            } else if item.runs && Seen::of(&item.target) != found.before {\n                return Err(changed_during_update(&item.target));\n            } else {", "if item.runs && Seen::of(&item.target) != found.before {\n                return Err(changed_during_update(&item.target));\n            } else if measure(&item.target).is_ok_and(|(_, sum)| sum == item.entry.sha256) {\n                report.unchanged.push(item.component);\n            } else {", *PLANTED, "a_run_that_waited_out_another_reads_what_it_left"),
    # G. A record says what it installed.
    (UPDATE + "install.rs", "if installed_hex != record.installed_sha256 {", "if false {", *PLANTED, "a_hand_installed_target_is_refused_and_kept"),
    # H. The hold is a file beside the binary.
    (UPDATE + "install.rs", "write_hold(&target, &record.to)?;", "let _ = write_hold as fn(&Path, &str) -> Result<(), Refusal>;", *PLANTED, "the_hold_survives_a_check_in_flight"),
    (UPDATE + "install.rs", "write_hold(&target, &record.to)?;", "let _ = write_hold as fn(&Path, &str) -> Result<(), Refusal>;", *PLANTED, "the_hold_needs_no_configuration_directory"),
    (UPDATE + "install.rs", "write_hold(&target, &record.to)?;", "let _ = write_hold(&target, &record.to);", *PLANTED, "a_hold_that_cannot_be_written_moves_nothing"),
    (UPDATE + "install.rs", "    write_hold(&target, &record.to)?;\n    put_in_place(&previous, &target).map_err(|e| Refusal::new(Why::InstallFailed, format!(\"{file} could not be put back: {e}; it is as it was\")))?;\n", "    put_in_place(&previous, &target).map_err(|e| Refusal::new(Why::InstallFailed, format!(\"{file} could not be put back: {e}; it is as it was\")))?;\n    write_hold(&target, &record.to)?;\n", *PLANTED, "a_hold_that_cannot_be_written_moves_nothing"),
    (UPDATE + "install.rs", "if asked == Asked::Auto {", "if false {", *PLANTED, "the_hold_survives_a_check_in_flight"),
    (UPDATE + "install.rs", "if asked == Asked::Auto {", "if false {", *PLANTED, "a_kill_at_each_step_of_a_rollback_keeps_the_hold_and_a_re_run_finishes"),
    (UPDATE + "install.rs", "if asked == Asked::Auto {", "if false {", *PLANTED, "a_hold_on_a_sibling_holds_only_that_sibling"),
    (UPDATE + "install.rs", "    sweep(&target);\n    let record = kept_for", "    let record = kept_for", *PLANTED, "a_kill_at_each_step_of_a_rollback_keeps_the_hold_and_a_re_run_finishes"),
    (UPDATE + "install.rs", "if *version <= held {", "if *version == held {", *PLANTED, "a_hold_leaves_what_it_names_and_anything_older_and_a_newer_one_passes"),
    (UPDATE + "install.rs", "if *version <= held {", "if true {", *PLANTED, "a_hold_leaves_what_it_names_and_anything_older_and_a_newer_one_passes"),
    (UPDATE + "install.rs", "let _ = fs::remove_file(with_suffix(&item.target, HOLD));", "", *PLANTED, "an_explicit_update_ends_the_hold_and_only_after_it_installs"),
    # I. One fetch.
    (UPDATE + "notice.rs", "let done = updater.install_alone(&found);", "let done = updater.update();", *PLANTED, "the_check_and_auto_agree_across_a_changing_server"),
    (UPDATE + "notice.rs", "if let Some(path) = moved {", "if let Some(path) = moved.or(report.available.then(String::new)) {", *PLANTED, "the_line_is_written_only_from_what_moved"),
    (UPDATE + "notice.rs", "Err(r) => r.components.iter().find(|o| o.component == updater.component && o.error.is_none()).map(|o| o.path.clone()),", "Err(_) => None,", *PLANTED, "the_line_is_written_only_from_what_moved"),
    (UPDATE + "notice.rs", "if report.available && auto {", "if auto {", *PLANTED, "update_auto_with_nothing_newer_does_nothing"),
    # J. A set override is the only address.
    (UPDATE + "config.rs", "Some(pin) => vec![pin.clone()],", "Some(pin) => std::iter::once(pin.clone()).chain(crate::MANIFEST_ADDRESSES.iter().map(|a| a.to_string())).collect(),", *PLANTED, "a_pin_is_the_only_address"),
    (UPDATE + "config.rs", "Some(pin) => vec![pin.clone()],", "Some(pin) => std::iter::once(pin.clone()).chain(crate::MANIFEST_ADDRESSES.iter().map(|a| a.to_string())).collect(),", *DOOR, "the_real_binary_asks_its_override_and_nothing_else"),
    # K. A sibling never blocks the running file.
    (UPDATE + "install.rs", "Err(r) => skipped.push(Skipped::of(name, r)),", "Err(r) => return Err(r),", *PLANTED, "a_later_shaped_sibling_beside_the_binary_does_not_block"),
    (UPDATE + "install.rs", "Err(r) => report.skipped.push(Skipped::of(&item.component, r)),", "Err(r) => return Err(said_after_prepare(r, &item)),", *PLANTED, "a_bad_sibling_file_is_skipped_and_the_running_file_goes_on"),
    (UPDATE + "install.rs", "if !is_bare_file_name(file) {", "if false {", *PLANTED, "a_file_name_cannot_leave_the_directory"),
    # L. Files we read or lock must be ours.
    (UPDATE + "install.rs", "custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)", "custom_flags(libc::O_NONBLOCK)", *PLANTED, "a_link_or_a_fifo_at_the_lock_is_refused"),
    (UPDATE + "install.rs", "custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)", "custom_flags(libc::O_NONBLOCK)", *PLANTED, "a_link_or_a_fifo_at_the_record_or_the_kept_file_is_refused"),
    (UPDATE + "install.rs", "custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)", "custom_flags(libc::O_NONBLOCK)", *PLANTED, "a_link_a_fifo_or_junk_at_the_hold_stops_auto_and_not_the_user"),
    (UPDATE + "install.rs", "custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)", "custom_flags(libc::O_NOFOLLOW)", *PLANTED, "a_link_or_a_fifo_at_the_record_or_the_kept_file_is_refused"),
    (UPDATE + "install.rs", "if !found.is_file() {", "if false {", *PLANTED, "a_link_or_a_fifo_at_the_lock_is_refused"),
    (UPDATE + "install.rs", "if found.uid() != unsafe { libc::geteuid() } {", "if false {", *PLANTED, "files_another_user_planted_in_a_sticky_directory_decide_nothing"),
    (UPDATE + "install.rs", 'Err(e) => return Err(Refusal::new(Why::NotOurs, format!("{} {e}", path.display()))),', "Err(_) => return Ok(lock),", *PLANTED, "a_link_a_fifo_or_junk_at_the_hold_stops_auto_and_not_the_user"),
    (UPDATE + "install.rs", "Err(r) if item.runs => return Err(r),\n                Err(r) => {", "Err(r) if !item.runs && r.why == Why::NotOurs => return Err(r),\n                Err(r) if item.runs => return Err(r),\n                Err(r) => {", *PLANTED, "a_plant_beside_a_sibling_makes_it_skipped"),
    # M. The sweep removes exact names only.
    (UPDATE + "install.rs", "#[cfg(not(windows))]\nfn sweep_asides(_target: &Path) {}", "#[cfg(not(windows))]\nfn sweep_asides(target: &Path) {\n    let prefix = format!(\"{}.aside-\", target.file_name().unwrap().to_string_lossy());\n    for e in fs::read_dir(target.parent().unwrap()).unwrap().flatten() {\n        if e.file_name().to_string_lossy().starts_with(&prefix) {\n            let _ = fs::remove_file(e.path());\n        }\n    }\n}", *PLANTED, "the_sweep_removes_exact_names_only"),
    (UPDATE + "install.rs", "    let file = std::path::absolute(file).map_err(|e| refused(format!(\"has no absolute path: {e}\")))?;\n", "", *PLANTED, "the_candidate_is_executed_by_absolute_path"),
    # N. Keep the chain.
    (UPDATE + "trust.rs", "let mut chain = walk(self.keys[..self.roots].to_vec(), written.chain.into_iter()).1;", "let mut chain = written.chain;", *PLANTED, "a_junk_chain_still_takes_a_real_key"),
    (UPDATE + "trust.rs", "let mut chain = walk(self.keys[..self.roots].to_vec(), written.chain.into_iter()).1;", "let _ = written;\n        let mut chain: Vec<Link> = Vec::new();", *PLANTED, "a_real_record_is_kept_when_another_is_appended"),
    (UPDATE + "trust.rs", "let Ok(written) = read_chain(dir) else { return };", "let written = read_chain(dir).unwrap_or_default();", *PLANTED, "a_chain_that_cannot_be_read_is_not_written_over"),
    (UPDATE + "trust.rs", "if bytes.len() as u64 > CHAIN_MAX_BYTES {\n        return Ok(Chain::default());", "if bytes.len() as u64 > CHAIN_MAX_BYTES {\n        return Err(std::io::Error::other(\"past the bound\"));", *PLANTED, "a_file_past_the_bound_is_cleaned_rather_than_kept"),
    # O. The release script, by real runs with the runner faked.
    ("scripts/release.py", 'target_dir = Path(json.loads(metadata)["target_directory"])', 'target_dir = ROOT / "target"', *RELEASE, "the_target_directory_is_where_cargo_says"),
    ("scripts/release.py", "        check_built(locate, version, args.publish)\n", "", *RELEASE, "a_host_binary_that_does_not_state_this_version_is_refused"),
    ("scripts/release.py", """print(f"ran wine {path} --version: {states_version(path, version, runner=('wine',))}")""", """print("ran wine, it is said")""", *RELEASE, "a_windows_binary_that_does_not_state_this_version_is_refused_when_wine_can_run_it"),
    # 1. All four are run, and only a dry run may leave one unrun.
    *[("scripts/release.py", "            path = locate(target, built)\n", f'            path = locate(target, built)\n            if built == "{name}": continue\n', *RELEASE, "each_of_the_four_built_files_must_state_this_version") for name in ("n0xis", "n0xis-mcp", "n0xis.exe", "n0xis-mcp.exe")],
    ("scripts/release.py", "            elif publishing:\n", "            elif False:\n", *RELEASE, "a_file_that_could_not_be_run_stops_a_publish"),
    ("scripts/release.py", "stdin=subprocess.DEVNULL, capture_output=True", "capture_output=True", *RELEASE, "a_built_file_runs_with_null_stdin_and_a_bound"),
    ("scripts/release.py", "timeout=RUN_BOUND, env=env)", "env=env)", *RELEASE, "a_built_file_runs_with_null_stdin_and_a_bound"),
    ("crates/n0xis-mcp/src/main.rs", 'if std::env::args_os().nth(1).is_some_and(|a| a == "--version") {', "if false {", *MCP, "version_answers_with_null_stdin"),
    ("scripts/release.py", "if stranded and not strand:", "if False:", *RELEASE, "a_change_of_key_that_strands_older_copies_is_refused"),
    ("scripts/release.py", "if stranded and not strand:", "if stranded:", *RELEASE, "stranding_older_copies_can_be_said_to_be_meant"),
    ("scripts/release.py", 'return key.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", key) else None', "return key.lower()", *RELEASE, "a_placeholder_or_no_file_at_the_previous_tag_is_no_constraint"),
    ("scripts/release.py", "    if not listed.stdout.strip():\n        return None\n", "", *RELEASE, "a_placeholder_or_no_file_at_the_previous_tag_is_no_constraint"),
    # 2. Every earlier key, not one tag back.
    ("scripts/release.py", "below = sorted(entry for entry in plain_tags() if entry[0] < version_numbers(version))", "below = sorted(entry for entry in plain_tags() if entry[0] < version_numbers(version))[-1:]", *RELEASE, "every_earlier_key_counts_and_not_only_the_newest"),
    ("scripts/release.py", "stranded = {key: tag for key, tag in keys_of_earlier_releases(version).items() if key not in public}", "stranded = dict(list((key, tag) for key, tag in keys_of_earlier_releases(version).items() if key not in public)[:1])", *RELEASE, "every_earlier_key_counts_and_not_only_the_newest"),
    ("scripts/release.py", 'return key.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", key) else None', 'return key if re.fullmatch(r"[0-9a-f]{64}", key) else None', *RELEASE, "a_key_in_capitals_counts_and_a_tag_that_is_not_plain_does_not"),
    ("scripts/release.py", 're.fullmatch(r"v(\\d+)\\.(\\d+)\\.(\\d+)", tag)', 're.match(r"v(\\d+)\\.(\\d+)\\.(\\d+)", tag)', *RELEASE, "a_key_in_capitals_counts_and_a_tag_that_is_not_plain_does_not"),
    ("scripts/release.py", '    key = key_in(shown.stdout, f"{TRUST_RELATIVE} at {tag}")\n', '    key = (re.findall(r\'RELEASE_PUBLIC_KEY: &str = "([^"]*)"\', shown.stdout) + [""])[0]\n', *RELEASE, "a_file_at_an_earlier_tag_that_cannot_be_read_is_refused"),
    ("scripts/release.py", "    if listed.returncode != 0:\n        refuse(unreadable)\n", "    if listed.returncode != 0:\n        return None\n", *RELEASE, "a_file_at_an_earlier_tag_that_cannot_be_read_is_refused"),
    # 3. Never below the highest, and the tag a failed upload left is not above it.
    ("scripts/release.py", "    if above:\n", "    if False:\n", *RELEASE, "a_version_below_any_tag_is_refused"),
    ("scripts/release.py", 'if numbers >= version_numbers(version) and tag != f"v{version}"]', 'if tag > f"v{version}"]', *RELEASE, "a_version_below_any_tag_is_refused"),
    ("scripts/release.py", 'if numbers >= version_numbers(version) and tag != f"v{version}"]', "if numbers >= version_numbers(version)]", *RELEASE, "a_failed_upload_prints_the_way_back_and_a_re_run_finishes"),
    ("scripts/release.py", "except subprocess.CalledProcessError as failed:", "except ZeroDivisionError as failed:", *RELEASE, "a_failed_upload_prints_the_way_back_and_a_re_run_finishes"),
    ("scripts/release.py", "state = check_existing_tag(tag) if exists else None", 'state = refuse(f"the tag {tag} already exists") if exists else None', *RELEASE, "a_failed_upload_prints_the_way_back_and_a_re_run_finishes"),
    ("scripts/release.py", 'if state == "draft":', "if False:", *RELEASE, "a_failed_upload_prints_the_way_back_and_a_re_run_finishes"),
    ("scripts/release.py", 'if at != commit("HEAD"):', "if False:", *RELEASE, "a_tag_elsewhere_or_already_published_is_refused"),
    ("scripts/release.py", 'if state == "published":', "if False:", *RELEASE, "a_tag_elsewhere_or_already_published_is_refused"),
    ("scripts/release.py", 'if "release not found" in p.stderr:', "if True:", *RELEASE, "a_tag_elsewhere_or_already_published_is_refused"),
    # The Windows sweep: a release has been run on a real Windows, or says that it has not.
    ("scripts/release.py", "    if windows_problem and args.publish:\n        refuse(windows_problem)\n", "", *RELEASE, "a_publish_with_no_sweep_of_these_binaries_is_refused"),
    ("scripts/release.py", '    if windows_problem:\n        print(f"NOT PUBLISHABLE: {windows_problem}")\n', "", *RELEASE, "a_publish_with_no_sweep_of_these_binaries_is_refused"),
    *[("scripts/release.py", 'for name in SWEPT_FILES if binaries.get(name)', f'for name in ("{name}",) if binaries.get(name)', *RELEASE, "a_sweep_speaks_only_for_the_bytes_it_ran_each_file_of_them") for name in ("n0xis.exe", "n0xis-mcp.exe")],
    ("scripts/release.py", "return None if other else sweep", "return sweep", *RELEASE, "a_sweep_speaks_only_for_the_bytes_it_ran_each_file_of_them"),
    ("scripts/release.py", "    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:\n        refuse(f\"the sweep record {path} cannot be read: {e!r}\")\n", "    except (OSError, ValueError, KeyError, TypeError, AttributeError):\n        return None\n", *RELEASE, "a_record_that_does_not_read_is_refused"),
    ("scripts/release.py", 'known = all(row["result"] in ("passed", "failed", "not-run") for row in rows)', "known = True", *RELEASE, "a_record_that_does_not_read_is_refused"),
    ("scripts/release.py", "readable = known and rows and isinstance", "readable = known and isinstance", *RELEASE, "a_record_that_does_not_read_is_refused"),
    ("scripts/release.py", "    if failed:\n        return f\"the Windows sweep of these binaries failed", "    if False:\n        return f\"the Windows sweep of these binaries failed", *RELEASE, "a_sweep_with_a_failure_or_a_command_with_no_case_is_refused"),
    ("scripts/release.py", "    if uncovered:\n        return f\"the Windows sweep has no case", "    if False:\n        return f\"the Windows sweep has no case", *RELEASE, "a_sweep_with_a_failure_or_a_command_with_no_case_is_refused"),
    ("scripts/release.py", 'f"{release_notes(version).rstrip()}\\n\\n{of_windows}" if of_windows else release_notes(version)', "release_notes(version)", *RELEASE, "a_clean_sweep_publishes_and_the_notes_say_what_ran_and_what_did_not"),
    ("scripts/release.py", "    if not_run:\n", "    if False:\n", *RELEASE, "a_clean_sweep_publishes_and_the_notes_say_what_ran_and_what_did_not"),
    ("scripts/release.py", "publish(args.tag, version, out, of_windows)", "publish(args.tag, version, out)", *RELEASE, "skipping_publishes_and_says_why_with_any_failure_beside_it"),
    ("scripts/release.py", "        if failed or uncovered:\n", "        if False:\n", *RELEASE, "skipping_publishes_and_says_why_with_any_failure_beside_it"),
    ("scripts/release.py", "if reason is not None and not reason.strip():", "if False:", *RELEASE, "skipping_needs_a_reason_and_something_to_skip"),
    ("scripts/release.py", "if sweep and not failed and not uncovered:", "if False:", *RELEASE, "skipping_needs_a_reason_and_something_to_skip"),
    # The doors: what a script can see.
    (UPDATE + "notice.rs", "if quiet || !std::io::stderr().is_terminal() || check_is_off_by_environment() {", "if quiet || check_is_off_by_environment() {", *DOOR, "in_a_pipe_there_is_no_request_no_line_and_nothing_is_read"),
    (UPDATE + "notice.rs", "if quiet || !std::io::stderr().is_terminal() || check_is_off_by_environment() {", "if quiet || check_is_off_by_environment() {", *DOOR, "stderr_joined_to_stdout_is_a_pipe_like_any_other"),
    (UPDATE + "notice.rs", "if quiet || !std::io::stderr().is_terminal() || check_is_off_by_environment() {", "if !std::io::stderr().is_terminal() || check_is_off_by_environment() {", *DOOR, "on_a_terminal::quiet_silences_it_and_starts_no_check"),
    (UPDATE + "notice.rs", "if quiet || !std::io::stderr().is_terminal() || check_is_off_by_environment() {", "if quiet || !std::io::stderr().is_terminal() {", *DOOR, "on_a_terminal::each_way_of_turning_it_off_turns_off_the_line_and_the_request"),
    (UPDATE + "notice.rs", "let Ok(settings) = Settings::load(&dir) else { return };", "let settings = Settings::load(&dir).unwrap_or_default();", *DOOR, "on_a_terminal::each_way_of_turning_it_off_turns_off_the_line_and_the_request"),
    (UPDATE + "notice.rs", 'let _ = writeln!(std::io::stderr(), "{line}");', 'let _ = writeln!(std::io::stdout(), "{line}");', *DOOR, "on_a_terminal::the_line_is_on_standard_error_once_a_day_and_changes_nothing_else"),
    (UPDATE + "notice.rs", 'let _ = writeln!(std::io::stderr(), "{line}");', 'let _ = writeln!(std::io::stderr(), "{line}"); std::process::exit(3);', *DOOR, "on_a_terminal::a_failing_command_exits_the_same_with_the_line_or_without_it"),
    (UPDATE + "notice.rs", "stamp.is_none_or(|at| at > now || now - at >= DAY_SECONDS)", "{ let _ = (stamp, now, DAY_SECONDS); true }", *DOOR, "on_a_terminal::the_line_is_on_standard_error_once_a_day_and_changes_nothing_else"),
    (UPDATE + "notice.rs", "stamp.is_none_or(|at| at > now || now - at >= DAY_SECONDS)", "{ let _ = (stamp, now, DAY_SECONDS); true }", *DOOR, "on_a_terminal::the_terminal_starts_one_check_a_day_in_the_background"),
    (UPDATE + "notice.rs", "child.arg(BACKGROUND_ARG).current_dir(dir).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());", "child.arg(BACKGROUND_ARG).current_dir(dir).stdin(Stdio::null()).stderr(Stdio::null());", *DOOR, "on_a_terminal::a_hung_address_delays_nothing_and_holds_no_pipe_open"),
    (UPDATE + "notice.rs", "let _ = child.spawn();", "let _ = child.status();", *DOOR, "on_a_terminal::a_hung_address_delays_nothing_and_holds_no_pipe_open"),
    (UPDATE + "notice.rs", "    let_go_of_inherited_handles();\n", "", *DOOR, "on_a_terminal::the_copy_lets_go_of_what_it_inherited"),
    (UPDATE + "notice.rs", "Some(i) if i.to == version && this_file == Some(i.path.as_str()) && stamp.spoken_of.as_ref() != Some(i) => {", "Some(i) if this_file == Some(i.path.as_str()) && stamp.spoken_of.as_ref() != Some(i) => {", *DOOR, "on_a_terminal::what_update_auto_installed_is_said_once_by_the_binary_that_was_installed"),
    # 5. The notice is about this file.
    (UPDATE + "notice.rs", "Some(i) if i.to == version && this_file == Some(i.path.as_str()) && stamp.spoken_of.as_ref() != Some(i) => {", "Some(i) if i.to == version && stamp.spoken_of.as_ref() != Some(i) => {", *DOOR, "on_a_terminal::the_notice_of_an_install_is_only_said_by_that_file"),
    (UPDATE + "notice.rs", "Some(i) if i.to == version && this_file == Some(i.path.as_str()) && stamp.spoken_of.as_ref() != Some(i) => {", "Some(i) if i.to == version && this_file == Some(i.path.as_str()) && stamp.spoken_of.as_ref().map(|s| &s.to) != Some(&i.to) => {", *DOOR, "on_a_terminal::the_notice_of_an_install_is_only_said_by_that_file"),
    (UPDATE + "notice.rs", ".find(|r| r.component == updater.component).map(|r| r.path.clone()),", '.find(|r| r.component == updater.component).map(|r| format!("{}-not", r.path)),', *PLANTED, "update_auto_installs_under_the_same_checks_and_rollback_holds_it"),
    ("crates/n0xis-cli/src/main.rs", "if !matches!(cli.command, Command::Update(_) | Command::Config(_)) {", "if true {", *DOOR, "on_a_terminal::neither_help_nor_version_nor_the_update_commands_say_it"),
    (UPDATE + "lib.rs", '["https://updates.structio.dev/n0xis/manifest.json", "https://github.com/Structio-labs/N0xis/releases/latest/download/manifest.json"];', '["https://github.com/Structio-labs/N0xis/releases/latest/download/manifest.json", "https://updates.structio.dev/n0xis/manifest.json"];', *DOOR, "the_real_binary_asks_the_frozen_addresses_in_order"),
    (UPDATE + "notice.rs", "        if !settings.check {\n            return None;\n        }\n        let latest = read_state(&dir).latest?;", "        let _ = settings.check;\n        let latest = read_state(&dir).latest?;", *MCP, "turned_off_means_not_said"),
    (UPDATE + "notice.rs", "(Version::parse(&latest).ok()? > Version::parse(version).ok()?).then_some(latest)", "Some(latest)", *MCP, "nothing_newer_states_the_version_only"),
]


def run_test(package, binary, test, cargo_args=()):
    cmd = ["systemd-run", "--user", "--scope", "-q", "--nice=19", "-p", "MemoryMax=6G", "--", "cargo", "test", "-p", package, *(("--test", binary) if binary else ("--lib",)), *cargo_args, "-j", "8", "--", "--exact", test]
    env = {"CARGO_PROFILE_TEST_DEBUG": "0"}
    p = subprocess.run(cmd, cwd=ROOT, env={**os.environ, **env}, capture_output=True, text=True, errors="replace")
    text = p.stdout + p.stderr
    if "could not compile" in text or re.search(r"^error(\[|:)", text, re.M) and "test result" not in text:
        return "does-not-compile", text
    if re.search(rf"^test {re.escape(test)} \.\.\. FAILED", text, re.M):
        return "failed", text
    if re.search(rf"^test {re.escape(test)} \.\.\. ok", text, re.M):
        return "passed", text
    return "no-such-test", text


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-k", help="only mutations whose file or test name contains this")
    args = ap.parse_args()
    chosen = [m for m in MUTATIONS if (not args.k or args.k in m[0] or args.k in m[5])]
    bad = []
    for path, anchor, replacement, package, binary, test in chosen:
        file = ROOT / path
        original = file.read_bytes()
        text = original.decode()
        assert text.count(anchor) == 1, f"{path}: the anchor is there {text.count(anchor)} times: {anchor}"
        try:
            file.write_text(text.replace(anchor, replacement))
            verdict, log = run_test(package, binary, test)
        finally:
            file.write_bytes(original)
        ok = verdict == "failed"
        print(f"{'ok    ' if ok else 'MISSED'} {verdict:<17} {test}  <-  {anchor[:60]!r}", flush=True)
        if not ok:
            bad.append((test, anchor, verdict))
            if verdict == "does-not-compile":
                errors = [l for l in log.splitlines() if l.startswith("error")]
                print("       " + " | ".join(errors[:3])[:300], flush=True)
    print(f"{len(chosen) - len(bad)} of {len(chosen)} failed on their own test")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
