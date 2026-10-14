// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The analysis DB (ROADMAP Phase 6): user/agent-asserted **names, type
//! notes, and comments** at an address, kept as **versioned truth** — every
//! change is appended to that address's `history` rather than silently
//! overwriting the previous value, so "what did we used to think this was"
//! is always answerable. Complements `patch` (Phase 2's already-versioned
//! byte-level journal, `applied`/`undone` with timestamps) rather than
//! replacing it — together they're the "names/types/comments/patches"
//! versioned truth ROADMAP Phase 6 asks for. Storage: a single
//! `.n0x/annotations.json` (`BTreeMap<va-hex, AnnotationRecord>`), same
//! storage-only split as [`selection`](crate::selection)/[`table`](crate::table).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use n0xis_contracts::Va;
use serde::{Deserialize, Serialize};

use crate::resolve;

fn now_unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// One recorded change to a single field of an [`AnnotationRecord`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationChange {
    /// `"name"` | `"type"` | `"comment"`.
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
    pub unix: u64,
}

/// The current facts about one address, plus the full history that produced
/// them. Any field can be absent (nothing asserted yet).
///
/// Variable annotations live in two pairs of maps, one per naming of stack
/// locals. A stack local's key is its synthesized name, and that name changed:
/// it was `local_<hex>` of the offset's **magnitude**, so the slots at `+8` and
/// `-8` were both `local_8`; it is now signed (`local_8`, `local_neg_8` —
/// `typeinfer::stack_local_name`). A rename saved under `local_8` before the
/// change may mean either slot, and read as a current key it silently lands on
/// `+8`, a different variable. So a key of the earlier naming is never stored
/// where current keys are: it is kept in [`Self::earlier_var_names`] /
/// [`Self::earlier_var_types`] and placed by [`Self::placed_vars`] among the
/// variables a function actually has. There is no version to consult in
/// memory; which map a key is in *is* which naming it was written under.
///
/// On disk the record is [`RecordOnDisk`], which carries that version as
/// `var_key_version`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(try_from = "RecordOnDisk", into = "RecordOnDisk")]
pub struct AnnotationRecord {
    pub va: Va,
    pub name: Option<String>,
    pub type_note: Option<String>,
    pub comment: Option<String>,
    /// Per-function local/parameter renames, keyed by the variable's **displayed**
    /// name in the decompiler (`local_78`, `rcx`, `v3`) → the user's chosen name.
    /// Lives on the function-start record (the `va` a decompile is addressed by),
    /// so one record carries the whole function's variable renames. Every key
    /// here is exact: it is the name the variable has now.
    pub var_names: BTreeMap<String, String>,
    /// Per-function C-type overrides, keyed by the variable's **synthesized**
    /// displayed name (`local_78`, `rcx`, `v3`) → a C-type string, plus the
    /// reserved key `"@return"` for the return type. Parallel to [`Self::var_names`].
    pub var_types: BTreeMap<String, String>,
    /// Renames stored under a key of the earlier stack-local naming that has
    /// not been settled onto one slot: never applied as an exact key, only
    /// placed by the earlier naming's rule ([`Self::placed_vars`]). Private, so
    /// nothing outside this module can move a key between the two namings.
    earlier_var_names: BTreeMap<String, String>,
    /// Types stored the same way. Parallel to [`Self::earlier_var_names`].
    earlier_var_types: BTreeMap<String, String>,
    /// User bookmark ("favorite") on this address — so a Bookmarks/Notes panel can
    /// list it even when nothing else is asserted here (a plain "remember this
    /// line/function"). A function rename or a line comment is already navigable;
    /// this flag is for addresses the user marks without renaming/commenting.
    pub bookmark: bool,
    pub history: Vec<AnnotationChange>,
}

/// The variable-key naming every record is written under now: stack locals
/// named by sign. A record without `var_key_version` is version 1, the
/// magnitude naming; version 1 is never written.
const VAR_KEY_VERSION: u64 = 2;

/// An [`AnnotationRecord`] as `annotations.json` (and every answer that
/// carries a record) spells it.
#[derive(Serialize, Deserialize)]
struct RecordOnDisk {
    va: Va,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    type_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    var_names: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    var_types: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    earlier_var_names: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    earlier_var_types: BTreeMap<String, String>,
    /// Which naming the keys of `var_names` / `var_types` were written under.
    /// Absent: version 1, a file from before the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    var_key_version: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    bookmark: bool,
    #[serde(default)]
    history: Vec<AnnotationChange>,
}

impl TryFrom<RecordOnDisk> for AnnotationRecord {
    type Error = String;

    /// A version-1 record's keys are sorted by naming as they are read: every
    /// key the naming change reinterprets goes to the earlier maps, and the
    /// rest — keys the two namings spell alike — stay exact. A version this
    /// build does not know is an error, not a guess: reading a newer naming's
    /// keys by an older rule is the wrong answer the version exists to prevent.
    fn try_from(d: RecordOnDisk) -> std::result::Result<Self, String> {
        let mut record = AnnotationRecord {
            va: d.va,
            name: d.name,
            type_note: d.type_note,
            comment: d.comment,
            var_names: d.var_names,
            var_types: d.var_types,
            earlier_var_names: d.earlier_var_names,
            earlier_var_types: d.earlier_var_types,
            bookmark: d.bookmark,
            history: d.history,
        };
        match d.var_key_version {
            None | Some(1) => {
                for which in VarMap::BOTH {
                    let reinterpreted: Vec<String> = which.of(&record).keys().filter(|k| reinterpreted(k)).cloned().collect();
                    for key in reinterpreted {
                        let value = which.of_mut(&mut record).remove(&key).unwrap_or_default();
                        if which.earlier_mut(&mut record).insert(key.clone(), value).is_some() {
                            // Only a hand-edited file can get here; dropping either
                            // value would lose one the user saved.
                            return Err(format!(
                                "the record at {} holds `{key}` both as a version-1 key and under earlier_var_{}s",
                                record.va,
                                which.label()
                            ));
                        }
                    }
                }
            }
            Some(VAR_KEY_VERSION) => {}
            Some(other) => {
                return Err(format!(
                    "the record at {} has var_key_version {other}, which is newer than this build reads (it knows 1 and {VAR_KEY_VERSION})",
                    record.va
                ));
            }
        }
        Ok(record)
    }
}

impl From<AnnotationRecord> for RecordOnDisk {
    fn from(r: AnnotationRecord) -> Self {
        RecordOnDisk {
            va: r.va,
            name: r.name,
            type_note: r.type_note,
            comment: r.comment,
            var_names: r.var_names,
            var_types: r.var_types,
            earlier_var_names: r.earlier_var_names,
            earlier_var_types: r.earlier_var_types,
            var_key_version: Some(VAR_KEY_VERSION),
            bookmark: r.bookmark,
            history: r.history,
        }
    }
}

/// Whether the naming change gave `key` a different reading: the earlier
/// naming printed it, and the slots it meant are not just itself (`local_8`
/// was `+8` or `-8`; `local_0` is `local_0` either way).
fn reinterpreted(key: &str) -> bool {
    n0xis_core::earlier_stack_local_slots(key).is_some_and(|slots| !(slots.len() == 1 && slots[0] == key))
}

/// The slots an earlier-naming key could mean, by their current names. A key
/// that reached the earlier maps by hand without being one of that naming's
/// stands for itself.
fn earlier_candidates(key: &str) -> Vec<String> {
    n0xis_core::earlier_stack_local_slots(key).unwrap_or_else(|| vec![key.to_string()])
}

/// One of a record's two kinds of variable annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VarMap {
    Names,
    Types,
}

impl VarMap {
    const BOTH: [VarMap; 2] = [VarMap::Names, VarMap::Types];

    /// The exact map.
    fn of(self, record: &AnnotationRecord) -> &BTreeMap<String, String> {
        match self {
            VarMap::Names => &record.var_names,
            VarMap::Types => &record.var_types,
        }
    }

    fn of_mut(self, record: &mut AnnotationRecord) -> &mut BTreeMap<String, String> {
        match self {
            VarMap::Names => &mut record.var_names,
            VarMap::Types => &mut record.var_types,
        }
    }

    /// The earlier-naming map.
    fn earlier(self, record: &AnnotationRecord) -> &BTreeMap<String, String> {
        match self {
            VarMap::Names => &record.earlier_var_names,
            VarMap::Types => &record.earlier_var_types,
        }
    }

    fn earlier_mut(self, record: &mut AnnotationRecord) -> &mut BTreeMap<String, String> {
        match self {
            VarMap::Names => &mut record.earlier_var_names,
            VarMap::Types => &mut record.earlier_var_types,
        }
    }

    fn of_placed(self, placed: &mut PlacedVars) -> &mut BTreeMap<String, String> {
        match self {
            VarMap::Names => &mut placed.var_names,
            VarMap::Types => &mut placed.var_types,
        }
    }

    /// The history field a change to one entry is recorded under (`var:<key>`).
    fn history_prefix(self) -> &'static str {
        match self {
            VarMap::Names => "var",
            VarMap::Types => "vartype",
        }
    }

    /// What the value is, for a sentence.
    fn label(self) -> &'static str {
        match self {
            VarMap::Names => "name",
            VarMap::Types => "type",
        }
    }

    /// The command that stores one, for a note telling the user how to re-apply it.
    fn command(self) -> &'static str {
        match self {
            VarMap::Names => "annotate var",
            VarMap::Types => "annotate vartype",
        }
    }
}

/// What became of one earlier-naming annotation among a function's variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EarlierOutcome {
    /// The function has exactly one of the candidates, and no value of its own
    /// stored under that slot's name: applied there.
    Applied(String),
    /// The function has more than one candidate: applying it to one would be
    /// a guess, so it is applied to none.
    Ambiguous(Vec<String>),
    /// The function has exactly one candidate, but that slot carries its own
    /// value stored under its current name, which wins.
    Taken(String),
    /// The function has none of the candidates.
    Absent,
    /// No function was looked at (no image was named).
    Unchecked,
}

/// One earlier-naming annotation and what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlierVar {
    which: VarMap,
    pub key: String,
    pub value: String,
    /// The slots the key could mean, by their current names.
    pub candidates: Vec<String>,
    pub outcome: EarlierOutcome,
}

impl EarlierVar {
    /// `"name"` or `"type"`.
    pub fn field(&self) -> &'static str {
        self.which.label()
    }

    /// The sentence every answer that shows the function's annotations
    /// carries for it — the decompile, `annotate show`, a variable write.
    pub fn note(&self) -> String {
        let EarlierVar { which, key, value, candidates, outcome } = self;
        let field = which.label();
        let head = format!(
            "variable {field} `{value}` is stored under `{key}`, a key of the earlier stack-local naming, which gave {} that one name",
            quoted(candidates)
        );
        match outcome {
            EarlierOutcome::Applied(slot) => format!(
                "{head}; this function has only `{slot}`, so it is applied there, and the next variable write to this function stores it under `{slot}`"
            ),
            EarlierOutcome::Ambiguous(present) => format!(
                "{head}; this function has {}, so it is applied to none — re-apply it to the one it meant (`{} --var <one> --value '{value}'`)",
                quoted(present),
                which.command()
            ),
            EarlierOutcome::Taken(slot) => format!(
                "{head}; this function has only `{slot}`, which has its own {field} stored under that name, so `{key}` is not applied"
            ),
            EarlierOutcome::Absent => format!("{head}; this function has none of them, so it is not applied"),
            EarlierOutcome::Unchecked => {
                format!("{head}; it applies only where the function has exactly one of them — name the image (`--file`) to see which")
            }
        }
    }
}

fn quoted(names: &[String]) -> String {
    names.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(" and ")
}

/// A record's variable annotations as they apply to one function: keyed by the
/// names the function's variables have now, plus what became of every
/// earlier-naming one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlacedVars {
    pub var_names: BTreeMap<String, String>,
    pub var_types: BTreeMap<String, String>,
    pub earlier: Vec<EarlierVar>,
}

impl PlacedVars {
    /// One sentence per earlier-naming annotation.
    pub fn notes(&self) -> Vec<String> {
        self.earlier.iter().map(EarlierVar::note).collect()
    }
}

/// What a variable write stored, and what became of the record's
/// earlier-naming annotations among the function's variables.
#[derive(Debug, Clone)]
pub struct VarWrite {
    pub record: AnnotationRecord,
    pub earlier: Vec<EarlierVar>,
}

impl AnnotationRecord {
    /// **The** earlier naming's rule: where entry `key` of the earlier map
    /// `which` lands among `function_vars` (the keys of the variables the
    /// function has; `None` when there is no function to look at). Every
    /// reader of a record's variable annotations and the rekeying on write
    /// ask here.
    fn place_earlier(&self, which: VarMap, key: &str, function_vars: Option<&BTreeSet<String>>) -> EarlierOutcome {
        let Some(vars) = function_vars else { return EarlierOutcome::Unchecked };
        let present: Vec<String> = earlier_candidates(key).into_iter().filter(|s| vars.contains(s)).collect();
        match present.as_slice() {
            [] => EarlierOutcome::Absent,
            [slot] if which.of(self).contains_key(slot) => EarlierOutcome::Taken(slot.clone()),
            [slot] => EarlierOutcome::Applied(slot.clone()),
            _ => EarlierOutcome::Ambiguous(present),
        }
    }

    /// Whether placing this record's variable annotations needs the function's
    /// variables: it holds an earlier-naming one. A record without one applies
    /// the same whatever the function has.
    pub fn needs_function_vars(&self) -> bool {
        !(self.earlier_var_names.is_empty() && self.earlier_var_types.is_empty())
    }

    /// This record's variable annotations placed among the variables the
    /// function has. Exact keys apply as they are; an earlier-naming key
    /// lands per [`Self::place_earlier`] and is reported either way.
    /// `function_vars` answers the variables' keys, or `None` when there is no
    /// function to look at; it is called only when the record holds an
    /// earlier-naming annotation ([`Self::needs_function_vars`]), so a reader
    /// pays for listing the variables only when the answer can change.
    pub fn placed_vars<E>(
        &self,
        function_vars: impl FnOnce() -> std::result::Result<Option<BTreeSet<String>>, E>,
    ) -> std::result::Result<PlacedVars, E> {
        let vars = if self.needs_function_vars() { function_vars()? } else { None };
        Ok(self.place_among(vars.as_ref()))
    }

    fn place_among(&self, function_vars: Option<&BTreeSet<String>>) -> PlacedVars {
        let mut out = PlacedVars::default();
        for which in VarMap::BOTH {
            for (key, value) in which.of(self) {
                which.of_placed(&mut out).insert(key.clone(), value.clone());
            }
        }
        for which in VarMap::BOTH {
            for (key, value) in which.earlier(self) {
                let outcome = self.place_earlier(which, key, function_vars);
                if let EarlierOutcome::Applied(slot) = &outcome {
                    which.of_placed(&mut out).insert(slot.clone(), value.clone());
                }
                out.earlier.push(EarlierVar {
                    which,
                    key: key.clone(),
                    value: value.clone(),
                    candidates: earlier_candidates(key),
                    outcome,
                });
            }
        }
        out
    }

    /// Settle what `function_vars` can settle: every earlier-naming entry that
    /// lands on one slot moves to the exact map under that slot's name,
    /// recorded in history as `var-key` / `vartype-key` (old key → new key).
    /// The value is untouched, and every other earlier entry stays where it is;
    /// nothing is ever dropped.
    fn rekey(&mut self, function_vars: Option<&BTreeSet<String>>) {
        let moves: Vec<(VarMap, String, String)> = VarMap::BOTH
            .into_iter()
            .flat_map(|which| which.earlier(self).keys().map(move |k| (which, k.clone())))
            .filter_map(|(which, key)| match self.place_earlier(which, &key, function_vars) {
                EarlierOutcome::Applied(slot) => Some((which, key, slot)),
                _ => None,
            })
            .collect();
        for (which, key, slot) in moves {
            let Some(value) = which.earlier_mut(self).remove(&key) else { continue };
            which.of_mut(self).insert(slot.clone(), value);
            self.history.push(AnnotationChange {
                field: format!("{}-key", which.history_prefix()),
                old: Some(key),
                new: Some(slot),
                unix: now_unix_secs(),
            });
        }
    }
}

fn path() -> Result<std::path::PathBuf> {
    Ok(resolve()?.dir.join("annotations.json"))
}

fn load_all() -> Result<BTreeMap<String, AnnotationRecord>> {
    let path = path()?;
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn save_all(records: &BTreeMap<String, AnnotationRecord>) -> Result<()> {
    let path = path()?;
    let json = serde_json::to_string_pretty(records).context("serialize annotations.json")?;
    fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// Set one field (`"name"`, `"type"`, or `"comment"`) on the record at `va`,
/// appending a history entry iff the value actually changes. `value: None`
/// clears the field (still recorded in history, so "we un-named this" is
/// visible too). Returns the updated record.
fn set_field(va: Va, field: &str, value: Option<String>) -> Result<AnnotationRecord> {
    let mut all = load_all()?;
    let key = va.to_string();
    let record = all.entry(key).or_insert_with(|| AnnotationRecord { va, ..Default::default() });

    let old = match field {
        "name" => record.name.clone(),
        "type" => record.type_note.clone(),
        "comment" => record.comment.clone(),
        other => anyhow::bail!("unknown annotation field '{other}'"),
    };
    if old != value {
        record.history.push(AnnotationChange { field: field.to_string(), old, new: value.clone(), unix: now_unix_secs() });
        match field {
            "name" => record.name = value,
            "type" => record.type_note = value,
            "comment" => record.comment = value,
            _ => unreachable!(),
        }
    }
    let result = record.clone();
    save_all(&all)?;
    Ok(result)
}

pub fn set_name(va: Va, name: Option<String>) -> Result<AnnotationRecord> {
    set_field(va, "name", name)
}
pub fn set_type(va: Va, type_note: Option<String>) -> Result<AnnotationRecord> {
    set_field(va, "type", type_note)
}
pub fn set_comment(va: Va, comment: Option<String>) -> Result<AnnotationRecord> {
    set_field(va, "comment", comment)
}

/// Rename (or, with `value: None`, clear) one decompiled variable on the function
/// whose start is `va`. `key` is the variable's current **displayed** name
/// (`local_78`, `rcx`, `v3`). Appended to history as `var:<key>` so the rename is
/// versioned truth like every other annotation.
///
/// `function_vars` answers the keys of the variables the function has, or
/// `None` when there is no function to look at; it is asked only when the
/// record holds an earlier-naming annotation. With them, each such
/// annotation that lands on one slot is first settled under that slot's name
/// ([`AnnotationRecord::placed_vars`] says where each lands).
pub fn set_var_name<E: std::fmt::Display>(
    va: Va,
    key: &str,
    value: Option<String>,
    function_vars: impl FnOnce() -> std::result::Result<Option<BTreeSet<String>>, E>,
) -> Result<VarWrite> {
    set_var(va, VarMap::Names, key, value, function_vars)
}

/// Set (or, with `value: None`/empty, clear) one variable's C type on the
/// function at `va`. `key` is the variable's displayed name (`local_78`, `rcx`,
/// `v3`) or the reserved `"@return"`. Appended to history as `vartype:<key>`.
/// `function_vars` as for [`set_var_name`].
pub fn set_var_type<E: std::fmt::Display>(
    va: Va,
    key: &str,
    value: Option<String>,
    function_vars: impl FnOnce() -> std::result::Result<Option<BTreeSet<String>>, E>,
) -> Result<VarWrite> {
    set_var(va, VarMap::Types, key, value, function_vars)
}

fn set_var<E: std::fmt::Display>(
    va: Va,
    which: VarMap,
    key: &str,
    value: Option<String>,
    function_vars: impl FnOnce() -> std::result::Result<Option<BTreeSet<String>>, E>,
) -> Result<VarWrite> {
    let mut all = load_all()?;
    let record = all.entry(va.to_string()).or_insert_with(|| AnnotationRecord { va, ..Default::default() });
    let vars = if record.needs_function_vars() {
        function_vars().map_err(|e| anyhow::anyhow!("the function's variables could not be listed: {e}"))?
    } else {
        None
    };
    record.rekey(vars.as_ref());
    // `key` is a current name: it goes to the exact map, and an earlier-naming
    // value stored under the same spelling stays where it is.
    let old = which.of(record).get(key).cloned();
    if old != value {
        record.history.push(AnnotationChange {
            field: format!("{}:{key}", which.history_prefix()),
            old,
            new: value.clone(),
            unix: now_unix_secs(),
        });
        match value {
            Some(v) if !v.trim().is_empty() => {
                which.of_mut(record).insert(key.to_string(), v);
            }
            _ => {
                which.of_mut(record).remove(key);
            }
        }
    }
    let write = VarWrite { record: record.clone(), earlier: record.place_among(vars.as_ref()).earlier };
    save_all(&all)?;
    Ok(write)
}

/// Set (or clear) the bookmark flag on `va`. Recorded in history like any other
/// field so "when did we bookmark this" is answerable.
pub fn set_bookmark(va: Va, on: bool) -> Result<AnnotationRecord> {
    let mut all = load_all()?;
    let record = all.entry(va.to_string()).or_insert_with(|| AnnotationRecord { va, ..Default::default() });
    if record.bookmark != on {
        record.history.push(AnnotationChange {
            field: "bookmark".to_string(),
            old: Some(record.bookmark.to_string()),
            new: Some(on.to_string()),
            unix: now_unix_secs(),
        });
        record.bookmark = on;
    }
    let result = record.clone();
    save_all(&all)?;
    Ok(result)
}

/// The record at `va`, if anything has ever been asserted about it.
pub fn get(va: Va) -> Result<Option<AnnotationRecord>> {
    Ok(load_all()?.remove(&va.to_string()))
}

/// Every annotated address, va-sorted (the map is already keyed that way
/// since `Va::to_string()` zero-pads implicitly via consistent hex width —
/// re-sorted numerically here to be robust regardless).
pub fn list() -> Result<Vec<AnnotationRecord>> {
    let mut records: Vec<AnnotationRecord> = load_all()?.into_values().collect();
    records.sort_by_key(|r| r.va.0);
    Ok(records)
}

/// Drop every field and the full history at `va`. Returns `true` if a record existed.
pub fn remove(va: Va) -> Result<bool> {
    let mut all = load_all()?;
    let removed = all.remove(&va.to_string()).is_some();
    if removed {
        save_all(&all)?;
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
            "n0xis-annotate-test-{}",
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
    fn set_name_type_comment_and_read_back() {
        in_temp_project(|| {
            assert!(get(Va(0x1000)).unwrap().is_none());

            let rec = set_name(Va(0x1000), Some("parse_header".to_string())).unwrap();
            assert_eq!(rec.name.as_deref(), Some("parse_header"));
            assert_eq!(rec.history.len(), 1);

            let rec = set_type(Va(0x1000), Some("int(char*, size_t)".to_string())).unwrap();
            assert_eq!(rec.type_note.as_deref(), Some("int(char*, size_t)"));
            let rec = set_comment(Va(0x1000), Some("bounds-checks then parses".to_string())).unwrap();
            assert_eq!(rec.comment.as_deref(), Some("bounds-checks then parses"));
            assert_eq!(rec.history.len(), 3, "one history entry per distinct field set");

            let fetched = get(Va(0x1000)).unwrap().expect("record exists");
            assert_eq!(fetched.name.as_deref(), Some("parse_header"));
            assert_eq!(fetched.type_note.as_deref(), Some("int(char*, size_t)"));
        });
    }

    #[test]
    fn renaming_never_loses_the_old_name_versioned_truth() {
        in_temp_project(|| {
            set_name(Va(0x2000), Some("sub_2000".to_string())).unwrap();
            let rec = set_name(Va(0x2000), Some("compute_checksum".to_string())).unwrap();
            assert_eq!(rec.name.as_deref(), Some("compute_checksum"));
            assert_eq!(rec.history.len(), 2);
            assert_eq!(rec.history[0].old, None);
            assert_eq!(rec.history[0].new.as_deref(), Some("sub_2000"));
            assert_eq!(rec.history[1].old.as_deref(), Some("sub_2000"));
            assert_eq!(rec.history[1].new.as_deref(), Some("compute_checksum"));
        });
    }

    #[test]
    fn setting_the_same_value_again_does_not_grow_history() {
        in_temp_project(|| {
            set_name(Va(0x3000), Some("f".to_string())).unwrap();
            let rec = set_name(Va(0x3000), Some("f".to_string())).unwrap();
            assert_eq!(rec.history.len(), 1, "idempotent set must not add a duplicate history entry");
        });
    }

    fn vars(keys: &[&str]) -> BTreeSet<String> {
        keys.iter().map(|k| k.to_string()).collect()
    }

    fn names(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// A record as a file from before `var_key_version` holds it.
    fn version_1(var_names: &[(&str, &str)]) -> AnnotationRecord {
        serde_json::from_value(serde_json::json!({ "va": "0x1000", "var_names": names(var_names) })).unwrap()
    }

    fn placed(record: &AnnotationRecord, function_vars: Option<&[&str]>) -> PlacedVars {
        record.placed_vars(|| Ok::<_, ()>(function_vars.map(vars))).unwrap()
    }

    fn outcomes(placed: &PlacedVars) -> Vec<(&str, &EarlierOutcome)> {
        placed.earlier.iter().map(|e| (e.key.as_str(), &e.outcome)).collect()
    }

    /// Plant a whole `annotations.json` in the temp project.
    fn plant(records: &[AnnotationRecord]) {
        save_all(&records.iter().map(|r| (r.va.to_string(), r.clone())).collect()).unwrap();
    }

    /// The four places a version-1 `local_<hex>` can land, by which of its two
    /// slots the function has — every one reported — and the keys the change
    /// did not touch, exact and silent.
    #[test]
    fn an_earlier_stack_local_key_lands_by_the_slots_the_function_has() {
        let record = version_1(&[("local_8", "saved"), ("rcx", "counter"), ("local_neg_10", "kept")]);
        let untouched = names(&[("rcx", "counter"), ("local_neg_10", "kept")]);

        let only_above = placed(&record, Some(&["local_8", "rcx"]));
        assert_eq!(only_above.var_names, names(&[("local_8", "saved"), ("rcx", "counter"), ("local_neg_10", "kept")]));
        assert_eq!(outcomes(&only_above), vec![("local_8", &EarlierOutcome::Applied("local_8".into()))]);

        let only_below = placed(&record, Some(&["local_neg_8", "rcx"]));
        assert_eq!(only_below.var_names, names(&[("local_neg_8", "saved"), ("rcx", "counter"), ("local_neg_10", "kept")]));
        assert_eq!(outcomes(&only_below), vec![("local_8", &EarlierOutcome::Applied("local_neg_8".into()))]);

        let both = placed(&record, Some(&["local_8", "local_neg_8"]));
        assert_eq!(both.var_names, untouched, "applied to neither");
        let both_slots = vec!["local_8".to_string(), "local_neg_8".to_string()];
        assert_eq!(outcomes(&both), vec![("local_8", &EarlierOutcome::Ambiguous(both_slots))]);
        let note = &both.notes()[0];
        assert!(note.contains("`local_8`") && note.contains("`local_neg_8`") && note.contains("saved"), "{note}");

        let neither = placed(&record, Some(&["local_10"]));
        assert_eq!(neither.var_names, untouched);
        assert_eq!(outcomes(&neither), vec![("local_8", &EarlierOutcome::Absent)]);
    }

    /// A key written now is exact: `local_8` is the `+8` slot, though the
    /// function has `-8` too, and nothing about it depends on the function.
    #[test]
    fn a_current_stack_local_key_is_exact() {
        let json = serde_json::json!({ "va": "0x1000", "var_names": { "local_8": "now" }, "var_key_version": 2 });
        let record: AnnotationRecord = serde_json::from_value(json).unwrap();
        assert!(!record.needs_function_vars(), "nothing in it depends on the function");
        let both = placed(&record, Some(&["local_8", "local_neg_8"]));
        assert_eq!(both.var_names, names(&[("local_8", "now")]));
        assert!(both.earlier.is_empty());
    }

    /// The one slot an earlier key can mean already has its own value under
    /// its current name: that one is applied, the earlier one reported. With
    /// no function to look at, an earlier key is reported, not guessed.
    #[test]
    fn an_earlier_key_is_never_applied_over_a_current_value_or_without_a_function() {
        let mut record = version_1(&[("local_8", "earlier")]);
        record.var_names.insert("local_neg_8".into(), "current".into());
        let below = placed(&record, Some(&["local_neg_8"]));
        assert_eq!(below.var_names, names(&[("local_neg_8", "current")]));
        assert_eq!(outcomes(&below), vec![("local_8", &EarlierOutcome::Taken("local_neg_8".into()))]);

        let unchecked = placed(&version_1(&[("local_8", "earlier")]), None);
        assert!(unchecked.var_names.is_empty());
        assert_eq!(outcomes(&unchecked), vec![("local_8", &EarlierOutcome::Unchecked)]);
    }

    /// Reading a version-1 record sorts its keys by naming: a key the change
    /// reinterprets goes aside, one the two namings spell alike stays exact.
    /// Every record is written as version 2 and reads back the same; a
    /// version this build does not know is refused.
    #[test]
    fn a_version_1_record_reads_into_two_namings_and_writes_as_version_2() {
        let record = version_1(&[("local_8", "a"), ("local_0", "b"), ("local_neg_8", "c"), ("rcx", "d"), ("local_8000000000000000", "e")]);
        assert_eq!(record.var_names, names(&[("local_0", "b"), ("local_neg_8", "c"), ("rcx", "d")]));
        assert_eq!(record.earlier_var_names, names(&[("local_8", "a"), ("local_8000000000000000", "e")]));

        let written = serde_json::to_value(&record).unwrap();
        assert_eq!(written["var_key_version"], 2);
        assert_eq!(written["earlier_var_names"]["local_8"], "a");
        let again: AnnotationRecord = serde_json::from_value(written.clone()).unwrap();
        assert_eq!(serde_json::to_value(&again).unwrap(), written, "a version-2 record reads back as written");

        let newer = serde_json::json!({ "va": "0x1000", "var_key_version": 99 });
        let refused = serde_json::from_value::<AnnotationRecord>(newer).unwrap_err().to_string();
        assert!(refused.contains("99"), "{refused}");
        let doubled = serde_json::json!({ "va": "0x1000", "var_names": { "local_8": "a" }, "earlier_var_names": { "local_8": "b" } });
        assert!(serde_json::from_value::<AnnotationRecord>(doubled).is_err(), "never drops one of two values for a key");
    }

    /// A write settles every earlier key that lands on one slot under that
    /// slot's name, value and all, and records the move.
    #[test]
    fn a_variable_write_settles_what_the_function_settles() {
        in_temp_project(|| {
            let mut record = version_1(&[("local_8", "saved")]);
            record.earlier_var_types = names(&[("local_8", "int64_t")]);
            plant(&[record]);

            let write = set_var_name(Va(0x1000), "rcx", Some("counter".into()), || Ok::<_, String>(Some(vars(&["local_neg_8", "rcx"])))).unwrap();
            let record = write.record;
            assert_eq!(record.var_names, names(&[("local_neg_8", "saved"), ("rcx", "counter")]));
            assert_eq!(record.var_types, names(&[("local_neg_8", "int64_t")]));
            assert!(!record.needs_function_vars(), "nothing left under the earlier naming");
            assert!(write.earlier.is_empty());
            let moves: Vec<(&str, Option<&str>, Option<&str>)> =
                record.history.iter().filter(|h| h.field.ends_with("-key")).map(|h| (h.field.as_str(), h.old.as_deref(), h.new.as_deref())).collect();
            assert_eq!(moves, vec![("var-key", Some("local_8"), Some("local_neg_8")), ("vartype-key", Some("local_8"), Some("local_neg_8"))]);
        });
    }

    /// An ambiguous earlier key survives a write to the same spelling: the new
    /// value is the `+8` slot's, the earlier one stays aside with its note,
    /// and both are on disk.
    #[test]
    fn an_ambiguous_earlier_key_survives_a_write_to_the_same_name() {
        in_temp_project(|| {
            plant(&[version_1(&[("local_8", "earlier")])]);
            let both = || Ok::<_, String>(Some(vars(&["local_8", "local_neg_8"])));
            let write = set_var_name(Va(0x1000), "local_8", Some("current".into()), both).unwrap();
            assert_eq!(write.record.var_names, names(&[("local_8", "current")]));
            assert_eq!(write.record.earlier_var_names, names(&[("local_8", "earlier")]));
            assert!(matches!(write.earlier[0].outcome, EarlierOutcome::Ambiguous(_)), "{:?}", write.earlier);

            let raw: serde_json::Value = serde_json::from_str(&fs::read_to_string(path().unwrap()).unwrap()).unwrap();
            assert_eq!(raw["0x1000"]["var_key_version"], 2);
            assert_eq!(raw["0x1000"]["var_names"]["local_8"], "current");
            assert_eq!(raw["0x1000"]["earlier_var_names"]["local_8"], "earlier");
        });
    }

    /// A write with no image settles nothing and keeps the earlier key aside;
    /// a later write whose image has one of its slots settles it.
    #[test]
    fn a_later_write_settles_a_key_once_the_image_disambiguates() {
        in_temp_project(|| {
            plant(&[version_1(&[("local_8", "earlier")])]);
            let unchecked = set_var_name(Va(0x1000), "rcx", Some("counter".into()), || Ok::<_, String>(None)).unwrap();
            assert_eq!(unchecked.record.earlier_var_names, names(&[("local_8", "earlier")]));
            assert_eq!(unchecked.earlier[0].outcome, EarlierOutcome::Unchecked);

            let settled = set_var_type(Va(0x1000), "rcx", Some("int".into()), || Ok::<_, String>(Some(vars(&["local_neg_8", "rcx"])))).unwrap();
            assert_eq!(settled.record.var_names, names(&[("local_neg_8", "earlier"), ("rcx", "counter")]));
            assert!(settled.record.earlier_var_names.is_empty());
        });
    }

    /// A store this build cannot read is never written over: a record of a
    /// newer version at one address makes every read fail and every write to
    /// any address fail, and the file keeps its bytes.
    #[test]
    fn an_unreadable_store_refuses_every_write() {
        in_temp_project(|| {
            let newer = r#"{ "0x2000": { "va": "0x2000", "var_names": { "local_8": "kept" }, "var_key_version": 99 } }"#;
            fs::write(path().unwrap(), newer).unwrap();
            assert!(get(Va(0x1000)).is_err());
            assert!(list().is_err());
            assert!(set_name(Va(0x1000), Some("f".into())).is_err());
            assert!(set_var_name(Va(0x1000), "rcx", Some("x".into()), || Ok::<_, String>(None)).is_err());
            assert!(set_bookmark(Va(0x1000), true).is_err());
            assert!(remove(Va(0x2000)).is_err());
            assert_eq!(fs::read_to_string(path().unwrap()).unwrap(), newer, "the file keeps its bytes");
        });
    }

    #[test]
    fn list_is_va_sorted_and_remove_drops_everything() {
        in_temp_project(|| {
            set_name(Va(0x3000), Some("c".to_string())).unwrap();
            set_name(Va(0x1000), Some("a".to_string())).unwrap();
            set_name(Va(0x2000), Some("b".to_string())).unwrap();
            let all = list().unwrap();
            assert_eq!(all.iter().map(|r| r.va).collect::<Vec<_>>(), vec![Va(0x1000), Va(0x2000), Va(0x3000)]);

            assert!(remove(Va(0x2000)).unwrap());
            assert!(!remove(Va(0x2000)).unwrap(), "already removed");
            assert_eq!(list().unwrap().len(), 2);
        });
    }
}
