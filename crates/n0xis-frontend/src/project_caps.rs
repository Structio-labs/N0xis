// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Project-database capabilities: annotations, selections, dumps and `.n0xt`
//! tables.
//!
//! These differ from the analysis capabilities in [`crate::registry`] in one
//! way that matters: they never resolve a source or an ISA. They read and
//! write `.n0x/` — the project *is* the target. Everything else is the same
//! contract, which is the point: from a frontend's side, `annotate.set` and
//! `decomp.pseudo` are the same kind of call.

use n0xis_contracts::{Response, TableEntry, TableLocator, TableValueType, Va, schema};
use serde_json::{Value, json};

use crate::registry::{Capability, Origin, Plugin, Registry};

fn err_pair(code: &str, msg: impl Into<String>) -> Response<Value> {
    Response::error(code, msg)
}

/// Argument helpers return `(code, message)` rather than a whole `Response`:
/// the envelope's `Err` arm is ~200 bytes, which is a lot to carry on every
/// argument lookup. Callers turn the pair into an envelope at the boundary.
type ArgErr = (&'static str, String);

fn to_env(e: ArgErr) -> Response<Value> {
    err_pair(e.0, e.1)
}

fn addr_of(args: &Value, key: &str) -> Result<Va, ArgErr> {
    match args.get(key).and_then(|v| v.as_str()) {
        Some(s) => Va::parse(s).map_err(|e| ("bad-addr", e.to_string())),
        None => Err(("missing-arg", format!("'{key}' is required"))),
    }
}

fn str_of<'a>(args: &'a Value, key: &str) -> Result<&'a str, ArgErr> {
    args.get(key).and_then(|v| v.as_str()).ok_or(("missing-arg", format!("'{key}' is required")))
}

fn ok<T: serde::Serialize>(schema_id: &str, data: T) -> Response<Value> {
    match serde_json::to_value(data) {
        Ok(v) => Response::success(schema_id, v),
        Err(e) => err_pair("serialize", e.to_string()),
    }
}

fn parse_table_type(name: &str) -> Result<TableValueType, String> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "i8" => TableValueType::I8,
        "u8" => TableValueType::U8,
        "i16" => TableValueType::I16,
        "u16" => TableValueType::U16,
        "i32" => TableValueType::I32,
        "u32" => TableValueType::U32,
        "i64" => TableValueType::I64,
        "u64" => TableValueType::U64,
        "f32" => TableValueType::F32,
        "f64" => TableValueType::F64,
        other => return Err(format!("unknown value type '{other}'")),
    })
}

/// Annotations, selections, dumps and tables — the `.n0x/` database as
/// capabilities.
pub struct ProjectOps;

impl Plugin for ProjectOps {
    fn name(&self) -> &str {
        "n0xis.project-ops"
    }

    fn register(&self, reg: &mut Registry) {
        // --- annotations -------------------------------------------------

        reg.add(Capability::new(
            "annotate.set",
            "Record a `name`, `type` or `comment` at an address. `field` picks which; prior values are kept as history.",
            Some(schema::v1::ANNOTATION),
            Origin::Builtin,
            Box::new(|args| {
                let va = match addr_of(args, "addr") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                // `None` clears the field — the CLI's optional `--value` maps
                // straight through, so "unset" stays expressible.
                let value = args.get("value").and_then(|v| v.as_str()).map(str::to_string);
                let result = match args.get("field").and_then(|v| v.as_str()).unwrap_or("name") {
                    "name" => n0xis_project::annotate::set_name(va, value),
                    "type" => n0xis_project::annotate::set_type(va, value),
                    "comment" => n0xis_project::annotate::set_comment(va, value),
                    other => return err_pair("bad-field", format!("unknown field '{other}' (name|type|comment)")),
                };
                match result {
                    Ok(rec) => ok(schema::v1::ANNOTATION, rec),
                    Err(e) => err_pair("annotate-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "annotate.var",
            "Rename (or clear) one decompiled variable on the function at `addr`. `var` is the variable's current displayed name (`local_78`, `rcx`, `v3`); omit `value` to clear.",
            Some(schema::v1::ANNOTATION),
            Origin::Builtin,
            Box::new(|args| {
                let va = match addr_of(args, "addr") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                let Some(key) = args.get("var").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) else {
                    return err_pair("bad-var", "`var` (the variable's displayed name) is required".to_string());
                };
                let value = args.get("value").and_then(|v| v.as_str()).map(str::to_string);
                match n0xis_project::annotate::set_var_name(va, key, value) {
                    Ok(rec) => ok(schema::v1::ANNOTATION, rec),
                    Err(e) => err_pair("annotate-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "type.struct",
            "Define (or replace) a named struct: `{name, size?, fields:[{offset,name,ctype?}]}`. The decompiler renders `p->name` for a pointer typed to it.",
            Some(schema::v1::TYPES),
            Origin::Builtin,
            Box::new(|args| match serde_json::from_value::<n0xis_project::types_db::StructDef>(args.clone()) {
                Ok(def) => match n0xis_project::types_db::put_struct(def) {
                    Ok(()) => ok(schema::v1::TYPES, json!({ "ok": true })),
                    Err(e) => err_pair("type-failed", e.to_string()),
                },
                Err(e) => err_pair("bad-struct", e.to_string()),
            }),
        ));

        reg.add(Capability::new(
            "type.enum",
            "Define (or replace) a named enum: `{name, members:[{name,value}]}`.",
            Some(schema::v1::TYPES),
            Origin::Builtin,
            Box::new(|args| match serde_json::from_value::<n0xis_project::types_db::EnumDef>(args.clone()) {
                Ok(def) => match n0xis_project::types_db::put_enum(def) {
                    Ok(()) => ok(schema::v1::TYPES, json!({ "ok": true })),
                    Err(e) => err_pair("type-failed", e.to_string()),
                },
                Err(e) => err_pair("bad-enum", e.to_string()),
            }),
        ));

        reg.add(Capability::new(
            "type.list",
            "Every defined struct and enum in the project.",
            Some(schema::v1::TYPES),
            Origin::Builtin,
            Box::new(|_args| match n0xis_project::types_db::load() {
                Ok(db) => ok(schema::v1::TYPES, json!({ "structs": db.structs, "enums": db.enums })),
                Err(e) => err_pair("type-failed", e.to_string()),
            }),
        ));

        reg.add(Capability::new(
            "type.rm",
            "Remove a struct or enum by name.",
            Some(schema::v1::TYPES),
            Origin::Builtin,
            Box::new(|args| {
                let Some(name) = args.get("name").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) else {
                    return err_pair("bad-name", "`name` is required".to_string());
                };
                match n0xis_project::types_db::remove(name) {
                    Ok(removed) => ok(schema::v1::TYPES, json!({ "removed": removed })),
                    Err(e) => err_pair("type-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "annotate.vartype",
            "Set (or clear) the C type of one variable/param/return on the function at `addr`. `var` is the displayed name or `@return`; omit `value` to clear. Applied in the decompiler's signature and declarations.",
            Some(schema::v1::ANNOTATION),
            Origin::Builtin,
            Box::new(|args| {
                let va = match addr_of(args, "addr") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                let Some(key) = args.get("var").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) else {
                    return err_pair("bad-var", "`var` (the variable's displayed name, or @return) is required".to_string());
                };
                let value = args.get("value").and_then(|v| v.as_str()).map(str::to_string);
                match n0xis_project::annotate::set_var_type(va, key, value) {
                    Ok(rec) => ok(schema::v1::ANNOTATION, rec),
                    Err(e) => err_pair("annotate-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "annotate.bookmark",
            "Bookmark ('favorite') an address so it shows in the Bookmarks/Notes list. `on:false` removes it.",
            Some(schema::v1::ANNOTATION),
            Origin::Builtin,
            Box::new(|args| {
                let va = match addr_of(args, "addr") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                let on = args.get("on").and_then(|v| v.as_bool()).unwrap_or(true);
                match n0xis_project::annotate::set_bookmark(va, on) {
                    Ok(rec) => ok(schema::v1::ANNOTATION, rec),
                    Err(e) => err_pair("annotate-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "annotate.show",
            "Every annotation recorded at an address, including its history.",
            Some(schema::v1::ANNOTATION),
            Origin::Builtin,
            Box::new(|args| {
                let va = match addr_of(args, "addr") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                match n0xis_project::annotate::get(va) {
                    Ok(Some(rec)) => ok(schema::v1::ANNOTATION, rec),
                    Ok(None) => err_pair("not-found", format!("no annotations recorded at {va}")),
                    Err(e) => err_pair("annotate-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "annotate.list",
            "Every annotated address in the project.",
            Some(schema::v1::ANNOTATION),
            Origin::Builtin,
            Box::new(|_args| match n0xis_project::annotate::list() {
                Ok(records) => ok(schema::v1::ANNOTATION, json!({ "count": records.len(), "records": records })),
                Err(e) => err_pair("annotate-failed", e.to_string()),
            }),
        ));

        reg.add(Capability::new(
            "annotate.rm",
            "Drop every annotation at an address.",
            Some(schema::v1::ANNOTATION),
            Origin::Builtin,
            Box::new(|args| {
                let va = match addr_of(args, "addr") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                match n0xis_project::annotate::remove(va) {
                    Ok(removed) => ok(schema::v1::ANNOTATION, json!({ "va": va, "removed": removed })),
                    Err(e) => err_pair("annotate-failed", e.to_string()),
                }
            }),
        ));

        // --- selections ---------------------------------------------------

        reg.add(Capability::new(
            "selection.save",
            "Name an address range so later commands can refer to it.",
            Some(schema::v1::SELECTION),
            Origin::Builtin,
            Box::new(|args| {
                let name = match str_of(args, "name") {
                    Ok(v) => v.to_string(),
                    Err(e) => return to_env(e),
                };
                let start = match addr_of(args, "start") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                let end = match addr_of(args, "end") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                let label = args.get("label").and_then(|v| v.as_str()).map(str::to_string);
                match n0xis_project::selection::save(&name, start, end, label) {
                    Ok(rec) => ok(schema::v1::SELECTION, json!({ "op": "save", "selection": rec })),
                    Err(e) => err_pair("selection-save-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "selection.list",
            "Every named range in the project.",
            Some(schema::v1::SELECTION),
            Origin::Builtin,
            Box::new(|_args| match n0xis_project::selection::list() {
                Ok(items) => ok(schema::v1::SELECTION, json!({ "op": "list", "count": items.len(), "selections": items })),
                Err(e) => err_pair("selection-list-failed", e.to_string()),
            }),
        ));

        reg.add(Capability::new(
            "selection.show",
            "One named range.",
            Some(schema::v1::SELECTION),
            Origin::Builtin,
            Box::new(|args| {
                let name = match str_of(args, "name") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                match n0xis_project::selection::get(name) {
                    Ok(rec) => ok(schema::v1::SELECTION, json!({ "op": "show", "selection": rec })),
                    Err(e) => err_pair("selection-not-found", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "selection.clear",
            "Forget a named range.",
            Some(schema::v1::SELECTION),
            Origin::Builtin,
            Box::new(|args| {
                let name = match str_of(args, "name") {
                    Ok(v) => v.to_string(),
                    Err(e) => return to_env(e),
                };
                match n0xis_project::selection::remove(&name) {
                    Ok(true) => ok(schema::v1::SELECTION, json!({ "op": "clear", "name": name, "removed": true })),
                    Ok(false) => err_pair("selection-not-found", format!("no selection named '{name}'")),
                    Err(e) => err_pair("selection-clear-failed", e.to_string()),
                }
            }),
        ));

        // --- dumps ----------------------------------------------------------

        reg.add(Capability::new(
            "dump.save",
            "Store a payload under `.n0x/dumps/<kind>/<name>`. Content comes from `content` (text) or `file`.",
            Some(schema::v1::DUMP),
            Origin::Builtin,
            Box::new(|args| {
                let name = match str_of(args, "name") {
                    Ok(v) => v.to_string(),
                    Err(e) => return to_env(e),
                };
                let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("raw").to_string();
                // No stdin arm here on purpose: a capability is called with
                // arguments, not a pipe. The CLI still reads stdin and passes
                // the result in as `content`.
                let bytes: Vec<u8> = if let Some(c) = args.get("content").and_then(|v| v.as_str()) {
                    c.as_bytes().to_vec()
                } else if let Some(f) = args.get("file").and_then(|v| v.as_str()) {
                    match std::fs::read(f) {
                        Ok(b) => b,
                        Err(e) => return err_pair("read-failed", e.to_string()),
                    }
                } else {
                    return err_pair("missing-arg", "provide 'content' or 'file'");
                };
                let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
                match n0xis_project::dump::save(&name, &kind, &bytes, force) {
                    Ok(saved) => ok(schema::v1::DUMP, json!({ "op": "save", "dump": saved })),
                    Err(e) => err_pair("dump-save-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "dump.list",
            "Stored dumps, optionally filtered by `kind`.",
            Some(schema::v1::DUMP),
            Origin::Builtin,
            Box::new(|args| {
                let kind = args.get("kind").and_then(|v| v.as_str());
                match n0xis_project::dump::list(kind) {
                    Ok(items) => ok(schema::v1::DUMP, json!({ "op": "list", "count": items.len(), "items": items })),
                    Err(e) => err_pair("dump-list-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "dump.show",
            "A dump's contents: text as-is, `raw`/`hex` kinds as a bounded hex preview (`preview` bytes).",
            Some(schema::v1::DUMP),
            Origin::Builtin,
            Box::new(|args| {
                let name = match str_of(args, "name") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                let kind = args.get("kind").and_then(|v| v.as_str());
                let preview = args.get("preview").and_then(|v| v.as_u64()).map(|v| v as usize).unwrap_or(256);
                match n0xis_project::dump::show(name, kind) {
                    Ok(content) => {
                        let binaryish = content.kind == "raw" || content.kind == "hex";
                        let text = if binaryish {
                            let n = preview.min(content.bytes.len());
                            content.bytes[..n].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
                        } else {
                            String::from_utf8_lossy(&content.bytes).into_owned()
                        };
                        ok(
                            schema::v1::DUMP,
                            json!({
                                "op": "show",
                                "name": name,
                                "kind": content.kind,
                                "bytes": content.bytes.len(),
                                "truncated": binaryish && preview < content.bytes.len(),
                                "content": text,
                            }),
                        )
                    }
                    Err(e) => err_pair("dump-not-found", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "dump.rm",
            "Delete a stored dump.",
            Some(schema::v1::DUMP),
            Origin::Builtin,
            Box::new(|args| {
                let name = match str_of(args, "name") {
                    Ok(v) => v.to_string(),
                    Err(e) => return to_env(e),
                };
                let kind = args.get("kind").and_then(|v| v.as_str());
                match n0xis_project::dump::remove(&name, kind) {
                    Ok(removed) => ok(schema::v1::DUMP, json!({ "op": "rm", "name": name, "removed": removed })),
                    Err(e) => err_pair("dump-rm-failed", e.to_string()),
                }
            }),
        ));

        // --- .n0xt tables ---------------------------------------------------

        reg.add(Capability::new(
            "table.add",
            "Add (or overwrite, by name) a table entry with a fixed-address locator.",
            Some(schema::v1::TABLE),
            Origin::Builtin,
            Box::new(|args| {
                let table = match str_of(args, "table") {
                    Ok(v) => v.to_string(),
                    Err(e) => return to_env(e),
                };
                let name = match str_of(args, "name") {
                    Ok(v) => v.to_string(),
                    Err(e) => return to_env(e),
                };
                let va = match addr_of(args, "addr") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                let value_type = match parse_table_type(args.get("type").and_then(|v| v.as_str()).unwrap_or("i32")) {
                    Ok(t) => t,
                    Err(e) => return err_pair("bad-type", e),
                };
                let entry = TableEntry {
                    name,
                    locator: TableLocator::Address { va },
                    value_type,
                    description: args.get("description").and_then(|v| v.as_str()).map(str::to_string),
                    hotkey: None,
                    groups: Vec::new(),
                    frozen: false,
                    freeze_value: None,
                    provenance: Default::default(),
                    verification: Default::default(),
                };
                match n0xis_project::table::add_entry(&table, entry) {
                    Ok(t) => match serde_json::to_value(t) {
                        Ok(v) => Response::success(schema::v1::TABLE, v).with_source(format!("table:{table}")),
                        Err(e) => err_pair("serialize", e.to_string()),
                    },
                    Err(e) => err_pair("table-add-failed", e.to_string()),
                }
            }),
        ));

        reg.add(Capability::new(
            "table.list",
            "Table names, or one table's entries when `table` is given.",
            Some(schema::v1::TABLE),
            Origin::Builtin,
            Box::new(|args| match args.get("table").and_then(|v| v.as_str()) {
                Some(name) => match n0xis_project::table::load(name) {
                    Ok(t) => ok(schema::v1::TABLE, t),
                    Err(e) => err_pair("table-not-found", e.to_string()),
                },
                None => match n0xis_project::table::list() {
                    Ok(names) => ok(schema::v1::TABLE, json!({ "tables": names })),
                    Err(e) => err_pair("table-list-failed", e.to_string()),
                },
            }),
        ));

        reg.add(Capability::new(
            "table.show",
            "One table, or one entry within it when `name` is given.",
            Some(schema::v1::TABLE),
            Origin::Builtin,
            Box::new(|args| {
                let table_name = match str_of(args, "table") {
                    Ok(v) => v,
                    Err(e) => return to_env(e),
                };
                let table = match n0xis_project::table::load(table_name) {
                    Ok(t) => t,
                    Err(e) => return err_pair("table-not-found", e.to_string()),
                };
                match args.get("name").and_then(|v| v.as_str()) {
                    Some(name) => match table.entries.iter().find(|e| e.name.eq_ignore_ascii_case(name)) {
                        Some(entry) => ok(schema::v1::TABLE, entry),
                        None => err_pair("entry-not-found", format!("no entry named '{name}' in table '{table_name}'")),
                    },
                    None => ok(schema::v1::TABLE, table),
                }
            }),
        ));

        reg.add(Capability::new(
            "table.rm",
            "Remove one entry, or the whole table when `name` is omitted.",
            Some(schema::v1::TABLE),
            Origin::Builtin,
            Box::new(|args| {
                let table = match str_of(args, "table") {
                    Ok(v) => v.to_string(),
                    Err(e) => return to_env(e),
                };
                match args.get("name").and_then(|v| v.as_str()) {
                    Some(name) => match n0xis_project::table::remove_entry(&table, name) {
                        Ok(removed) => ok(schema::v1::TABLE, json!({ "removed": removed })),
                        Err(e) => err_pair("table-rm-failed", e.to_string()),
                    },
                    None => match n0xis_project::table::delete(&table) {
                        Ok(removed) => ok(schema::v1::TABLE, json!({ "removedTable": removed })),
                        Err(e) => err_pair("table-rm-failed", e.to_string()),
                    },
                }
            }),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;

    #[test]
    fn project_ops_register_under_their_own_plugin() {
        let mut reg = Registry::new();
        reg.add_plugin(&ProjectOps);
        for name in ["annotate.set", "annotate.list", "selection.save", "dump.list", "table.list"] {
            assert!(reg.get(name).is_some(), "{name} should be registered");
        }
        // A project-op still reports its origin like any other capability.
        assert_eq!(reg.get("annotate.set").unwrap().origin, Origin::Builtin);
    }

    #[test]
    fn a_missing_required_argument_is_an_envelope_not_a_panic() {
        let mut reg = Registry::new();
        reg.add_plugin(&ProjectOps);
        let v = serde_json::to_value(reg.dispatch("annotate.set", &json!({}))).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["code"], "missing-arg");
    }
}
