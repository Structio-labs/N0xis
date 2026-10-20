// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Registered analysis plugins under `.n0x/plugins.json` — durable `name` →
//! spawn command bindings an agent registers once
//! (`docs/COMMUNITY_ROADMAP.md`'s "Plugin system"). Storage only: actually
//! spawning a plugin and returning its findings is the registry's
//! job, same storage/logic split as [`selection`](crate::selection) and
//! [`patch`](crate::patch).

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::resolve;
use crate::store::write_replacing;

/// One registered plugin: a name, the argv to spawn it (a single string,
/// split via `n0xis_sources::split_command_line` at call time — the exact
/// same contract as `--remote-cmd`), and which artifact kind(s) it wants to
/// see on stdin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRecord {
    pub name: String,
    pub command: String,
    /// Artifact kinds this plugin declares it handles: any of
    /// `"cfg"` / `"pseudo"` / `"discover"` (`CfgArtifact` / `PseudoFunction` /
    /// `DiscoverArtifact`).
    pub handles: Vec<String>,
    pub created_at_unix: u64,
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The registry exists and could not be read or parsed, or the project that
/// holds it could not be resolved. Which plugins are registered is then
/// unknown — not "none", and not "no plugin by that name".
///
/// Its own type, separate from the `anyhow` errors of the writes, because the
/// doors must tell this state apart from an empty registry and from a missing
/// name, and each used to fold it into one of those: the capability registry
/// into "no plugins" (and so `unknown-capability`), MCP `plugin_run` into
/// `plugin-not-found`. The message and the [`code`](Self::CODE) are stated
/// here once, for every door that answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryUnreadable {
    /// The whole `anyhow` chain, `{:#}`: the file and the OS's or the
    /// parser's own reason ("read …/plugins.json: Permission denied (os
    /// error 13)").
    cause: String,
}

impl RegistryUnreadable {
    /// The error code a door answers with when it needed the registry and
    /// could not read it.
    pub const CODE: &'static str = "plugin-registry-unreadable";

    fn of(e: &anyhow::Error) -> Self {
        RegistryUnreadable { cause: format!("{e:#}") }
    }
}

impl std::fmt::Display for RegistryUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the plugin registry could not be read: {}", self.cause)
    }
}

impl std::error::Error for RegistryUnreadable {}

/// Every record, or why there is no answer. The one reader: [`list`],
/// [`for_kind`], [`get`], and the read-modify-write of [`add`] and [`remove`]
/// all come through here, so they cannot disagree about what "unreadable" is.
fn load_all() -> std::result::Result<Vec<PluginRecord>, RegistryUnreadable> {
    read_registry().map_err(|e| RegistryUnreadable::of(&e))
}

fn read_registry() -> Result<Vec<PluginRecord>> {
    let path = resolve()?.plugins_path();
    let Some(raw) = read_regular_file(&path)? else {
        return Ok(Vec::new());
    };
    // A registry with no plugins is `[]` — what a save of none writes. An
    // empty file is not that: it is a save that did not finish (saves were
    // written in place, truncating first, until `save_all` replaced the file
    // whole) or a file made by hand, and it was answered as "no plugins".
    if raw.trim().is_empty() {
        bail!("read {}: the file holds no JSON ({} bytes); a registry with no plugins is `[]`", path.display(), raw.len());
    }
    serde_json::from_str(&raw).context("parse plugins.json")
}

/// The text of the regular file at `path`, symbolic links followed; `None`
/// when nothing is at `path`, which is the one state that means "no
/// registry". Everything else that is not a readable regular file is an
/// error naming what is there.
///
/// Three states this tells apart that used to read as "no plugins" or hang:
/// - **A directory that cannot be searched.** `path.exists()` answered false
///   there (it is `metadata().is_ok()`). The error kind is what decides:
///   only `NotFound` means nothing is there.
/// - **A symbolic link to nothing.** Following it is `NotFound` too, so it
///   read as no registry; the link itself is there, and says where it points.
/// - **A FIFO** (or a socket or a device). Reading one blocks until a writer
///   comes — `capability list` hung, and every MCP tool call builds the
///   registry. A character device such as `/dev/zero` never ends. So the
///   kind is checked before the file is opened, since opening a FIFO for
///   reading is itself what blocks.
///
/// Checked before the open and again on the opened file: the second closes
/// the window in which the path is swapped for a device, which opens without
/// blocking. It does not close it for a FIFO swapped in between the two —
/// that open blocks before any check can run; refusing it needs a
/// non-blocking open, which needs an OS crate this crate does not link.
/// That window is open only to someone who can already write `.n0x/`.
fn read_regular_file(path: &Path) -> Result<Option<String>> {
    use std::io::Read;
    let ctx = || format!("read {}", path.display());
    match fs::metadata(path) {
        Ok(meta) => require_regular(&meta, path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return match fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Ok(_) => {
                    let to = fs::read_link(path).map(|t| t.display().to_string()).unwrap_or_else(|e| format!("? ({e})"));
                    bail!("read {}: it is a symbolic link to {to}, which does not exist", path.display())
                }
                Err(e) => Err(e).with_context(ctx),
            };
        }
        Err(e) => return Err(e).with_context(ctx),
    }
    let mut file = fs::File::open(path).with_context(ctx)?;
    require_regular(&file.metadata().with_context(ctx)?, path)?;
    let mut raw = String::new();
    file.read_to_string(&mut raw).with_context(ctx)?;
    Ok(Some(raw))
}

/// An error unless `meta` is a regular file's, naming what it is instead.
fn require_regular(meta: &fs::Metadata, path: &Path) -> Result<()> {
    if meta.is_file() {
        return Ok(());
    }
    bail!("read {}: not a regular file but {}; the registry is read only from a regular file", path.display(), file_kind(meta))
}

/// What a file that is not a regular one is, in words.
fn file_kind(meta: &fs::Metadata) -> &'static str {
    let ft = meta.file_type();
    if ft.is_dir() {
        return "a directory";
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() {
            return "a FIFO (named pipe)";
        }
        if ft.is_socket() {
            return "a socket";
        }
        if ft.is_char_device() {
            return "a character device";
        }
        if ft.is_block_device() {
            return "a block device";
        }
    }
    "something else"
}

/// Save every record, replacing the file whole ([`write_replacing`]): the
/// in-place `fs::write` this was could leave an empty registry behind when
/// interrupted, and an empty registry is now an error, not "no plugins".
fn save_all(records: &[PluginRecord]) -> Result<()> {
    let path = resolve()?.plugins_path();
    let json = serde_json::to_string_pretty(records).context("serialize plugins.json")?;
    write_replacing(&path, json.as_bytes())
}

/// Register (or overwrite, by name) a plugin.
pub fn add(name: &str, command: &str, handles: Vec<String>) -> Result<PluginRecord> {
    if name.is_empty() {
        bail!("plugin name must not be empty");
    }
    if command.trim().is_empty() {
        bail!("plugin command must not be empty");
    }
    let record = PluginRecord {
        name: name.to_string(),
        command: command.to_string(),
        handles,
        created_at_unix: now_unix_secs(),
    };
    let mut records = load_all()?;
    records.retain(|p| !p.name.eq_ignore_ascii_case(name));
    records.push(record.clone());
    save_all(&records)?;
    Ok(record)
}

/// All registered plugins, name-sorted.
pub fn list() -> std::result::Result<Vec<PluginRecord>, RegistryUnreadable> {
    let mut records = load_all()?;
    records.sort_by_key(|p| p.name.to_ascii_lowercase());
    Ok(records)
}

/// The canonical `n0xis.plugin.v1` list payload — one shape both front doors
/// emit. The CLI and the MCP `plugin_list` tool stamped the same `meta.schema`
/// but produced two `data` shapes: the CLI carried `op: "list"`, the MCP door
/// omitted it. Same schema, two payloads. This is the single builder that
/// closes that drift; callers wrap it in `Response::success(schema::v1::PLUGIN,
/// ...)` and emit it their own way.
pub fn list_payload() -> Result<serde_json::Value> {
    let items = list()?;
    let items_v = serde_json::to_value(&items).unwrap_or(serde_json::Value::Null);
    Ok(serde_json::json!({ "op": "list", "count": items.len(), "plugins": items_v }))
}

/// Every registered plugin that declares it handles `kind`
/// (`"cfg"`/`"pseudo"`/`"discover"`) — the artifact kind a caller names when
/// it invokes the plugin
/// runs.
pub fn for_kind(kind: &str) -> std::result::Result<Vec<PluginRecord>, RegistryUnreadable> {
    Ok(load_all()?
        .into_iter()
        .filter(|p| p.handles.iter().any(|h| h.eq_ignore_ascii_case(kind)))
        .collect())
}

/// A single plugin by name (case-insensitive): `Ok(None)` when the registry
/// was read and holds no such plugin, `Err` when it could not be read. This
/// returned one `anyhow` error for both, and MCP `plugin_run` answered
/// `plugin-not-found` for a registry it had not been able to read.
pub fn get(name: &str) -> std::result::Result<Option<PluginRecord>, RegistryUnreadable> {
    Ok(load_all()?.into_iter().find(|p| p.name.eq_ignore_ascii_case(name)))
}

/// Remove a plugin by name. Returns `true` if one was removed.
pub fn remove(name: &str) -> Result<bool> {
    let mut records = load_all()?;
    let before = records.len();
    records.retain(|p| !p.name.eq_ignore_ascii_case(name));
    let removed = records.len() != before;
    if removed {
        save_all(&records)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CWD_TEST_LOCK;

    fn in_temp_project<T>(f: impl FnOnce() -> T) -> T {
        let _guard = CWD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!(
            "n0xis-plugin-test-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(tmp.join(".n0x")).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        let result = f();
        std::env::set_current_dir(prev).unwrap();
        fs::remove_dir_all(&tmp).ok();
        result
    }

    #[test]
    fn add_list_get_remove_roundtrip() {
        in_temp_project(|| {
            add("vendor-sigs", "vendor-plugin --mode sigs", vec!["cfg".into()]).unwrap();
            add("annotator", "annotator-bin", vec!["pseudo".into(), "discover".into()]).unwrap();

            let all = list().unwrap();
            assert_eq!(all.len(), 2);
            assert_eq!(all[0].name, "annotator"); // name-sorted

            let p = get("VENDOR-SIGS").unwrap().expect("registered"); // case-insensitive
            assert_eq!(p.command, "vendor-plugin --mode sigs");

            let cfg_plugins = for_kind("cfg").unwrap();
            assert_eq!(cfg_plugins.len(), 1);
            assert_eq!(cfg_plugins[0].name, "vendor-sigs");

            assert!(remove("vendor-sigs").unwrap());
            assert!(!remove("vendor-sigs").unwrap(), "already removed");
            assert_eq!(list().unwrap().len(), 1);
        });
    }

    #[test]
    fn add_overwrites_same_name() {
        in_temp_project(|| {
            add("p", "old-cmd", vec!["cfg".into()]).unwrap();
            add("p", "new-cmd", vec!["pseudo".into()]).unwrap();
            let all = list().unwrap();
            assert_eq!(all.len(), 1, "overwrite, not append");
            assert_eq!(all[0].command, "new-cmd");
        });
    }

    /// A readable registry without the name is `Ok(None)`; one that does not
    /// parse is `Err`, so a door can answer the two differently. `get` gave
    /// one `anyhow` error for both, and MCP `plugin_run` called both
    /// `plugin-not-found`.
    #[test]
    fn a_missing_name_and_an_unreadable_registry_are_different_answers() {
        in_temp_project(|| {
            add("p", "some-plugin", vec!["cfg".into()]).unwrap();
            assert_eq!(get("other").map(|r| r.is_some()), Ok(false), "a readable registry without the name");

            fs::write(".n0x/plugins.json", "{ this is not json").unwrap();
            let err = get("p").expect_err("a registry that does not parse has no answer for any name");
            let text = err.to_string();
            assert!(
                text.starts_with("the plugin registry could not be read: parse plugins.json: ")
                    && text.contains("at line 1 column"),
                "the message must say the registry could not be read, and the parser's reason: {text}"
            );
        });
    }

    /// A 0-byte registry is not "no plugins": a registry with none is `[]`,
    /// and an empty file is a save that did not finish or a file made by
    /// hand. It was answered `Ok(vec![])`, the same as no file at all.
    #[test]
    fn an_empty_registry_file_is_unreadable_not_no_plugins() {
        in_temp_project(|| {
            fs::write(".n0x/plugins.json", "").unwrap();
            let text = list().expect_err("a 0-byte registry is not one with no plugins").to_string();
            assert!(
                text.starts_with("the plugin registry could not be read: read ") && text.contains("holds no JSON (0 bytes)"),
                "the message must say the file is empty: {text}"
            );
        });
    }

    /// A save never rewrites the registry in place: a hard link to the file
    /// as it was keeps its old contents, because the save wrote a new file and
    /// renamed it over the name. An in-place `fs::write` truncates the one
    /// file both names point at — the state an interrupted save leaves is
    /// then an empty registry. No temporary file is left behind.
    #[test]
    fn a_save_replaces_the_registry_and_never_rewrites_it_in_place() {
        in_temp_project(|| {
            add("first", "first-plugin", vec!["cfg".into()]).unwrap();
            fs::hard_link(".n0x/plugins.json", "before.json").unwrap();
            add("second", "second-plugin", vec!["cfg".into()]).unwrap();

            let before = fs::read_to_string("before.json").unwrap();
            assert!(
                !before.contains("second"),
                "the save wrote into the file that was there, so an interrupted save truncates the registry: {before}"
            );
            assert_eq!(list().unwrap().len(), 2, "the registry under its name has both");
            let left: Vec<String> = fs::read_dir(".n0x")
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| n != "plugins.json")
                .collect();
            assert!(left.is_empty(), "a save left files beside the registry: {left:?}");
        });
    }

    /// A registry that is a symbolic link to a file is written through, as an
    /// in-place write wrote through it: the link stays a link and the file it
    /// names gets the new record. Unix only: making a symbolic link on
    /// Windows needs a privilege a test cannot count on.
    #[cfg(unix)]
    #[test]
    fn a_save_through_a_symbolic_link_writes_the_file_it_names() {
        in_temp_project(|| {
            fs::create_dir("shared").unwrap();
            fs::write("shared/plugins.json", "[]").unwrap();
            let shared = std::env::current_dir().unwrap().join("shared/plugins.json");
            std::os::unix::fs::symlink(&shared, ".n0x/plugins.json").unwrap();

            add("p", "some-plugin", vec!["cfg".into()]).unwrap();

            let link = fs::symlink_metadata(".n0x/plugins.json").unwrap();
            assert!(link.file_type().is_symlink(), "the save replaced the link with a file of its own");
            assert!(fs::read_to_string(&shared).unwrap().contains("some-plugin"), "the file the link names was not written");
        });
    }

    /// A save keeps the registry's permissions: a rename puts a new file in
    /// place, with the permissions a new file gets, where an in-place write
    /// kept the old file's. Unix only: the mode bits are what is compared.
    #[cfg(unix)]
    #[test]
    fn a_save_keeps_the_registry_permissions() {
        use std::os::unix::fs::PermissionsExt;
        in_temp_project(|| {
            add("first", "first-plugin", vec!["cfg".into()]).unwrap();
            fs::set_permissions(".n0x/plugins.json", fs::Permissions::from_mode(0o600)).unwrap();
            add("second", "second-plugin", vec!["cfg".into()]).unwrap();
            let mode = fs::metadata(".n0x/plugins.json").unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the save changed the registry's permissions to {mode:o}");
        });
    }

    /// A read-only registry refuses a save, as it refused the in-place write;
    /// a rename, which the directory allows, would have replaced it.
    #[test]
    fn a_read_only_registry_refuses_a_save() {
        in_temp_project(|| {
            add("first", "first-plugin", vec!["cfg".into()]).unwrap();
            let path = std::path::Path::new(".n0x/plugins.json");
            let mut perms = fs::metadata(path).unwrap().permissions();
            perms.set_readonly(true);
            fs::set_permissions(path, perms.clone()).unwrap();
            let answer = add("second", "second-plugin", vec!["cfg".into()]);
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            fs::set_permissions(path, perms).unwrap();
            let err = answer.expect_err("a read-only registry was saved over");
            assert!(format!("{err:#}").contains("the file is read-only"), "{err:#}");
        });
    }

    /// Nothing at the path is no plugins; a symbolic link to nothing is a
    /// registry that cannot be read. Both were `NotFound` to the read, and
    /// both answered no plugins. Unix only, as above.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symbolic_link_is_unreadable_and_a_missing_path_is_no_plugins() {
        in_temp_project(|| {
            assert_eq!(list().unwrap().len(), 0, "no file at all: no plugins");
            std::os::unix::fs::symlink("nowhere/plugins.json", ".n0x/plugins.json").unwrap();
            let text = list().expect_err("a link to nothing is not a missing registry").to_string();
            assert!(
                text.contains("is a symbolic link to nowhere/plugins.json, which does not exist"),
                "the message must say the link names nothing: {text}"
            );
        });
    }

    /// A FIFO planted as the registry is refused at once. Reading it blocked
    /// until something wrote to it, and every door builds the registry, so
    /// `capability list` hung. Unix only: a FIFO is planted with `mkfifo`.
    ///
    /// The read runs on its own thread under a watchdog, so on code that
    /// blocks the test fails instead of hanging; the watchdog then opens the
    /// FIFO for writing and closes it, which ends the blocked read.
    #[cfg(unix)]
    #[test]
    fn a_fifo_as_the_registry_is_refused_without_blocking() {
        in_temp_project(|| {
            let fifo = std::env::current_dir().unwrap().join(".n0x/plugins.json");
            let made = std::process::Command::new("mkfifo").arg(&fifo).status();
            assert!(matches!(made, Ok(s) if s.success()), "precondition: `mkfifo` planted the FIFO ({made:?})");

            let (tx, rx) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                let _ = tx.send(list().map(|r| r.len()).map_err(|e| e.to_string()));
            });
            let answer = rx.recv_timeout(std::time::Duration::from_secs(5));
            if answer.is_err() {
                drop(fs::OpenOptions::new().write(true).open(&fifo));
            }
            let _ = reader.join();
            let answer = answer.expect("reading the registry blocked on a FIFO");
            let text = answer.expect_err("a FIFO is not a registry");
            assert!(text.contains("not a regular file but a FIFO (named pipe)"), "the message must say what is there: {text}");
        });
    }

    #[test]
    fn rejects_empty_command() {
        in_temp_project(|| {
            let err = add("bad", "", vec!["cfg".into()]).unwrap_err();
            assert!(err.to_string().contains("command must not be empty"));
        });
    }
}
