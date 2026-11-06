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

CLASSIFY = """        let mut changing = Vec::new();
        for item in plan {
            if measure(&item.target).is_ok_and(|(_, sum)| sum == item.entry.sha256) {
                report.unchanged.push(item.component);
            } else {
                changing.push(item);
            }
        }
"""
TAKE_LOCK = """        let first = &plan[0];
        let _lock = take_lock(&first.target, |e| not_writable(&first.target, &first.entry, e))?;
"""
TAKE_LOCK_AFTER = """        let Some(first) = changing.first() else { return Ok(report) };
        let _lock = take_lock(&first.target, |e| not_writable(&first.target, &first.entry, e))?;
"""
COMMENT = """        // What is installed is read only now, under the lock. Read before it, a run that waited out
        // another would go on to keep the new file as `.previous` and lose the old one.
"""
READ_UNDER_THE_LOCK = TAKE_LOCK + COMMENT + CLASSIFY
READ_BEFORE_THE_LOCK = CLASSIFY + TAKE_LOCK_AFTER

# (file, anchor, replacement, package, test binary, test name)
PLANTED = ("n0xis-update", "planted")
SETTINGS = ("n0xis-update", "settings")
DOOR = ("n0xis-cli", "update_door")
MCP = ("n0xis-mcp", "states_its_version_and_a_newer_one")
MUTATIONS = [
    (UPDATE + "net.rs", ".https_only(true)", ".https_only(false)", *PLANTED, "plain_http_is_refused_without_a_connection"),
    (UPDATE + "net.rs", ".https_only(true)", ".https_only(false)", *PLANTED, "a_redirect_to_plain_http_is_refused"),
    (UPDATE + "net.rs", ".https_only(true)", ".https_only(false)", *PLANTED, "a_file_at_a_plain_http_address_is_refused"),
    (UPDATE + "lib.rs", "self.trust.verify(&bytes, &signature)?;", "let _ = &signature;", *PLANTED, "a_bad_signature_is_refused"),
    (UPDATE + "lib.rs", "self.trust.verify(&bytes, &signature)?;", "let _ = &signature;", *PLANTED, "a_manifest_changed_after_signing_is_refused"),
    (UPDATE + "lib.rs", "self.trust.verify(&bytes, &signature)?;", "let _ = &signature;", *PLANTED, "the_placeholder_refuses_every_manifest_whatever_the_key_file_says"),
    (UPDATE + "trust.rs", "if signatures.is_empty() {", "if false {", *PLANTED, "no_signature_is_its_own_refusal"),
    (UPDATE + "lib.rs", "let signature = self.transport.get_signature(&format!(\"{address}{SIGNATURE_SUFFIX}\"))?;", "let signature = self.transport.get_signature(&format!(\"{address}{SIGNATURE_SUFFIX}\")).unwrap_or_else(|_| vec![b'0'; 128]);", *PLANTED, "no_signature_is_its_own_refusal"),
    (UPDATE + "trust.rs", "let Some(root) = from_hex::<32>(constant) else { return Trust { keys: Vec::new() } };", "let root = from_hex::<32>(constant).unwrap_or([7u8; 32]);", *PLANTED, "the_placeholder_refuses_every_manifest_whatever_the_key_file_says"),
    (UPDATE + "lib.rs", "self.trust.remember(self.config_dir.as_deref(), &bytes, &signature, key);", "let _ = key;", *PLANTED, "a_signed_manifest_can_name_the_next_key"),
    (UPDATE + "trust.rs", "if keys.iter().any(|key| signatures.iter().any(|sig| verifies(key, sig))) {", "if signatures.first().is_some_and(|sig| keys.iter().any(|key| verifies(key, sig))) {", *PLANTED, "either_of_two_signatures_is_enough"),
    (UPDATE + "install.rs", "if sum != item.entry.sha256 {", "if false {", *PLANTED, "a_tampered_file_is_refused"),
    (UPDATE + "install.rs", "if sum != item.entry.sha256 {", "if false {", *PLANTED, "a_wrong_digest_is_refused"),
    (UPDATE + "install.rs", "if sum != item.entry.sha256 {", "if false {", *PLANTED, "a_bad_second_file_leaves_the_first_alone"),
    (UPDATE + "manifest.rs", 'None | Some(Value::Null) => return Err(Refusal::new(Why::NoDigest, format!("{component}: the manifest gives no digest, so the file cannot be checked"))),', "None | Some(Value::Null) => [0u8; 32],", *PLANTED, "no_digest_is_its_own_refusal_not_a_passed_check"),
    (UPDATE + "net.rs", "if got != size {", "if false {", *PLANTED, "a_truncated_download_is_refused"),
    (UPDATE + "net.rs", "if got != size {", "if false {", *PLANTED, "a_claimed_size_past_what_is_sent_is_refused"),
    (UPDATE + "net.rs", "Err(e) if got < size && ended_early(&e) => {", "Err(e) if false && ended_early(&e) => {", *PLANTED, "a_truncated_download_is_refused"),
    (UPDATE + "net.rs", "if got > size {", "if false {", *PLANTED, "a_file_that_never_ends_stops_being_read_at_the_limit"),
    (UPDATE + "install.rs", "if manifest.version < self.current {", "if false {", *PLANTED, "an_older_version_is_refused_and_the_same_one_changes_nothing"),
    (UPDATE + "install.rs", "if manifest.version == self.current {", "if false {", *PLANTED, "an_older_version_is_refused_and_the_same_one_changes_nothing"),
    (UPDATE + "lib.rs", "worst = Some(worst.map_or(r.why, |w| w.max(r.why)));", "if self.addresses.len() > 1 { return Err(r); }", *PLANTED, "a_dead_first_address_falls_through_quietly"),
    (UPDATE + "lib.rs", "worst = Some(worst.map_or(r.why, |w| w.max(r.why)));", "if r.why != Why::ManifestUnavailable { return Err(r); }", *PLANTED, "a_first_address_answering_badly_does_not_strand_the_client"),
    (UPDATE + "lib.rs", "worst = Some(worst.map_or(r.why, |w| w.max(r.why)));", "worst = Some(r.why);", *PLANTED, "the_most_serious_failure_is_the_one_reported"),
    (UPDATE + "lib.rs", "available: newer && blocked.is_none(),", "available: newer,", *PLANTED, "no_entry_for_this_platform_is_a_refusal"),
    (UPDATE + "manifest.rs", 'value.get("next_key").and_then(Value::as_str).and_then(from_hex::<32>);', 'Some(value.get("next_key").map_or(Ok(None), |v| v.as_str().map(|s| from_hex::<32>(s)).ok_or_else(|| bad("next_key".to_string())))?).flatten();', *PLANTED, "unknown_fields_and_unknown_components_are_ignored"),
    (UPDATE + "install.rs", "let Some(target) = regular_file(&dir.join(file))? else { continue };", "let target = dir.join(file);", *PLANTED, "a_component_not_installed_is_not_added"),
    (UPDATE + "install.rs", "if measure(&item.target).is_ok_and(|(_, sum)| sum == item.entry.sha256) {", "if false {", *PLANTED, "a_component_that_did_not_change_is_not_fetched"),
    (UPDATE + "manifest.rs", '!name.is_empty() && name != "." && name != ".." && !name.contains([\'/\', \'\\\\\', \':\'])', "!name.is_empty()", *PLANTED, "a_file_name_cannot_leave_the_directory"),
    (UPDATE + "install.rs", "let _ = fs::remove_file(&self.0);", "let _ = &self.0;", *PLANTED, "a_tampered_file_is_refused"),
    (UPDATE + "install.rs", "        set_mode(&new_file.0, mode).map_err(disk)?;\n", "", *PLANTED, "a_newer_release_installs_keeps_the_old_file_and_rolls_back"),
    (UPDATE + "install.rs", "|e| not_writable(&first.target, &first.entry, e))?;", "|e| Refusal::new(Why::InstallFailed, e.to_string()))?;", *PLANTED, "a_directory_that_cannot_be_written_is_a_refusal_naming_the_file"),
    (UPDATE + "install.rs", '.with_hint(format!("fetch {} ({} bytes, sha256 {}) and put it at {} yourself", entry.url, entry.size,', '.with_hint(format!("fetch {} ({} bytes, sha256 {}) and put it at {} yourself", "it", entry.size,', *PLANTED, "a_directory_that_cannot_be_written_is_a_refusal_naming_the_file"),
    (UPDATE + "install.rs", "for target in others_of_the_same_install(&exe, &record.to) {", "for target in Vec::<PathBuf>::new() {", *PLANTED, "a_component_beside_the_binary_goes_with_it_and_comes_back_with_it"),
    (UPDATE + "net.rs", ".timeout_recv_response(Some(limits.response))", ".timeout_recv_response(None)", *PLANTED, "a_silent_server_ends_in_a_refusal_within_the_bound"),
    (UPDATE + "net.rs", ".timeout_recv_body(Some(body))", ".timeout_recv_body(None)", *PLANTED, "a_body_that_stalls_ends_in_a_refusal_within_the_bound"),
    (UPDATE + "net.rs", ".max_redirects(limits.redirects)", ".max_redirects(50)", *PLANTED, "a_redirect_over_https_is_followed_and_a_loop_is_bounded"),
    (UPDATE + "net.rs", ".max_redirects(limits.redirects)", ".max_redirects(1)", *PLANTED, "a_redirect_over_https_is_followed_and_a_loop_is_bounded"),
    (UPDATE + "net.rs", ".with_config().limit(max).read_to_vec()", ".with_config().limit(u64::MAX).read_to_vec()", *PLANTED, "an_endless_manifest_is_not_read_to_its_end"),
    (UPDATE + "notice.rs", "if report.available && auto && state.held.as_deref() != Some(report.latest.as_str()) {", "if report.available && auto {", *PLANTED, "update_auto_installs_under_the_same_checks_and_rollback_holds_it"),
    (UPDATE + "notice.rs", "if report.available && auto && state.held.as_deref() != Some(report.latest.as_str()) {", "if report.available {", *PLANTED, "the_daily_check_writes_what_it_learned_and_touches_nothing"),
    (UPDATE + "notice.rs", "state.latest = report.available.then(|| report.latest.clone());", "state.latest = Some(report.latest.clone());", *PLANTED, "the_daily_check_writes_what_it_learned_and_touches_nothing"),
    (UPDATE + "config.rs", 'Err(e) => Err(Refusal::new(Why::ConfigUnreadable, format!("{}: {e}", path.display()))),\n    }\n}', 'Err(_) => Ok(Map::new()),\n    }\n}', *SETTINGS, "a_damaged_file_is_refused_and_not_overwritten"),
    (UPDATE + "config.rs", '} else if value.starts_with("https://") {', "} else if true {", *SETTINGS, "a_bad_key_or_value_is_refused"),
    (UPDATE + "lib.rs", "for address in self.pin.iter().chain(&self.addresses) {", "for address in self.addresses.iter().chain(&self.pin) {", *DOOR, "the_real_binary_asks_its_override_then_the_frozen_addresses_in_order"),
    # A. Which manifest.
    (UPDATE + "lib.rs", "if best.as_ref().is_none_or(|(held, _)| manifest.version > held.version) {", "if best.is_none() {", *PLANTED, "a_stale_first_address_does_not_hide_a_newer_second"),
    (UPDATE + "lib.rs", "if self.pin.as_ref() == Some(address) {", "if false {", *PLANTED, "the_override_decides_alone_when_it_verifies"),
    (UPDATE + "lib.rs", "let manifest = Manifest::parse(&bytes)?;\n        if let Some(key) = manifest.next_key {", "let manifest = Manifest::parse(&bytes)?;\n        if let Some(key) = manifest.next_key.filter(|_| manifest.version.major > 1) {", *PLANTED, "a_next_key_is_remembered_from_a_manifest_that_did_not_win"),
    # B. A chain and not a list.
    (UPDATE + "trust.rs", "verify_under(keys, &manifest, link.signature.as_bytes()).ok()?;\n", "", *PLANTED, "a_planted_key_file_trusts_nothing"),
    (UPDATE + "trust.rs", "verify_under(keys, &manifest, link.signature.as_bytes()).ok()?;\n", "", *PLANTED, "a_two_hop_chain_does"),
    (UPDATE + "trust.rs", "                keys.push(key);\n", "                let _ = key;\n", *PLANTED, "a_two_hop_chain_does"),
    (UPDATE + "trust.rs", ".chain.iter().take(CHAIN_MAX_LINKS) {", ".chain.iter() {", *PLANTED, "a_key_file_past_its_bounds_proves_nothing_past_them"),
    (UPDATE + "trust.rs", "if read.is_err() || bytes.len() as u64 > CHAIN_MAX_BYTES {", "if read.is_err() {", *PLANTED, "a_key_file_past_its_bounds_proves_nothing_past_them"),
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
    (UPDATE + "install.rs", "if from_hex::<32>(&record.sha256) != Some(sum) {", "if false {", *PLANTED, "a_previous_that_does_not_match_is_refused"),
    (UPDATE + "install.rs", "if !metadata.is_file() {", "if false {", *PLANTED, "a_planted_previous_symlink_is_refused"),
    (UPDATE + "install.rs", "if kept_equals_target(&exe, &record) {", "if false {", *PLANTED, "a_previous_equal_to_the_target_says_that_nothing_changed"),
    (UPDATE + "install.rs", "let reads = Version::parse(&record.from).is_ok() && Version::parse(&record.to).is_ok() && from_hex::<32>(&record.sha256).is_some();", "let reads = from_hex::<32>(&record.sha256).is_some();", *PLANTED, "a_record_that_does_not_read_as_versions_is_no_record"),
    (UPDATE + "install.rs", "Err(TryLockError::WouldBlock) => return Err(Refusal::new(Why::UpdateInProgress, format!(\"another run holds {}\", path.display()))),", "Err(TryLockError::WouldBlock) => return Ok(file),", *PLANTED, "a_held_lock_stops_update_rollback_and_the_detached_copy"),
    (UPDATE + "notice.rs", "Err(r) if r.why == Why::UpdateInProgress => {}", "Err(r) if r.why == Why::NoEntry => {}", *PLANTED, "a_held_lock_stops_update_rollback_and_the_detached_copy"),
    (UPDATE + "install.rs", "Err(TryLockError::WouldBlock) => return Err(Refusal::new(Why::UpdateInProgress, format!(\"another run holds {}\", path.display()))),", "Err(TryLockError::WouldBlock) => return Ok(file),", *PLANTED, "parallel_runs_keep_the_old_file_for_rollback"),
    (UPDATE + "install.rs", "std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);", "std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o666);", *PLANTED, "the_new_file_is_0600_under_umask_000"),
    (UPDATE + "install.rs", "let (size, sum) = measure(&new_file.0).map_err(disk)?;", "let (size, sum) = (item.entry.size, item.entry.sha256);", *PLANTED, "a_file_altered_after_the_download_is_refused"),
    (UPDATE + "install.rs", "Ok(fs::metadata(target)?.permissions().mode() & 0o777)", "Ok(fs::metadata(target)?.permissions().mode() & 0o7777)", *PLANTED, "setuid_is_not_carried_over"),
    (UPDATE + "install.rs", "let real = if found.file_type().is_symlink() {", "let real = if false {", *PLANTED, "a_symlinked_sibling_stays_a_link_and_comes_back"),
    (UPDATE + "install.rs", "if fs::symlink_metadata(&real).is_ok_and(|m| m.is_file()) { Ok(Some(real)) } else { Err(strange(\"is not a regular file\".to_string())) }", "if fs::symlink_metadata(&real).is_ok_and(|m| m.is_file()) { Ok(Some(real)) } else { Ok(None) }", *PLANTED, "a_sibling_that_is_not_a_regular_file_is_refused"),
    (UPDATE + "install.rs", "    refusal.components = outcomes;\n", "    let _ = outcomes;\n", *PLANTED, "a_commit_failure_reports_each_component"),
    (UPDATE + "install.rs", "if is_other && read_record(&target).is_some_and(|r| r.to == to) {", "if is_other && read_record(&target).is_some() && !to.is_empty() {", *PLANTED, "a_sibling_from_an_earlier_install_stays_on_rollback"),
    (UPDATE + "install.rs", "for item in &changing {\n            sweep(&item.target);\n        }\n", "", *PLANTED, "what_a_dead_run_left_is_swept_under_the_lock"),
    # E. The small ones, and the push.
    (UPDATE + "install.rs", READ_UNDER_THE_LOCK, READ_BEFORE_THE_LOCK, *PLANTED, "a_run_that_waited_out_another_reads_what_it_left"),
    (UPDATE + "notice.rs", "entries.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect()", "{ let _ = entries; (3..1024).collect() }", *DOOR, "on_a_terminal::the_copy_lets_go_of_a_handle_above_1024"),
    (UPDATE + "notice.rs", "if lock.try_lock().is_err() || !a_day_has_passed(read_stamp(&path), at) {", "let _ = &lock;\n    if !a_day_has_passed(read_stamp(&path), at) {", *DOOR, "on_a_terminal::a_stamp_being_claimed_starts_no_second_check"),
    (UPDATE + "notice.rs", "installed: state.installed.filter(|i| is_version(&i.from) && is_version(&i.to)),", "installed: state.installed,", *DOOR, "on_a_terminal::an_escape_in_the_state_file_never_reaches_the_terminal"),
    ("scripts/release.py", 'run("git", "push", PUSH_TO, f"refs/tags/{tag}", cwd=ROOT)', 'run("git", "push", "origin", tag, cwd=ROOT)', "n0xis-update", "release_script", "publishing_pushes_only_the_tag_to_the_named_address"),
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
    (UPDATE + "notice.rs", "Some(i) if i.to == version && stamp.spoken_of.as_deref() != Some(i.to.as_str()) => {", "Some(i) if stamp.spoken_of.as_deref() != Some(i.to.as_str()) => {", *DOOR, "on_a_terminal::what_update_auto_installed_is_said_once_by_the_binary_that_was_installed"),
    ("crates/n0xis-cli/src/main.rs", "if !matches!(cli.command, Command::Update(_) | Command::Config(_)) {", "if true {", *DOOR, "on_a_terminal::neither_help_nor_version_nor_the_update_commands_say_it"),
    (UPDATE + "lib.rs", '["https://updates.structio.dev/n0xis/manifest.json", "https://github.com/Structio-labs/N0xis/releases/latest/download/manifest.json"];', '["https://github.com/Structio-labs/N0xis/releases/latest/download/manifest.json", "https://updates.structio.dev/n0xis/manifest.json"];', *DOOR, "the_real_binary_asks_its_override_then_the_frozen_addresses_in_order"),
    (UPDATE + "notice.rs", "        if !settings.check {\n            return None;\n        }\n        let latest = read_state(&dir).latest?;", "        let _ = settings.check;\n        let latest = read_state(&dir).latest?;", *MCP, "turned_off_means_not_said"),
    (UPDATE + "notice.rs", "(Version::parse(&latest).ok()? > Version::parse(version).ok()?).then_some(latest)", "Some(latest)", *MCP, "nothing_newer_states_the_version_only"),
]


def run_test(package, binary, test):
    cmd = ["systemd-run", "--user", "--scope", "-q", "--nice=19", "-p", "MemoryMax=6G", "--", "cargo", "test", "-p", package, "--test", binary, "-j", "8", "--", "--exact", test]
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
