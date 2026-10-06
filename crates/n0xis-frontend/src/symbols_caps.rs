// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Program databases (PDB) as capabilities: keeping one in the project's symbol
//! store, where `pdb_syms` finds it.

use std::path::Path;

use n0xis_contracts::{Response, schema};
use n0xis_sources::StaticImage;
use serde_json::{Value, json};

use crate::pdb_syms;
use crate::registry::{Capability, Origin, Plugin, Registry};

pub struct SymbolTools;

impl Plugin for SymbolTools {
    fn name(&self) -> &str {
        "n0xis.symbols"
    }

    fn register(&self, reg: &mut Registry) {
        reg.add(Capability::new(
            "symbols.add",
            "Keep a PDB in the project's symbol store, after checking that it belongs to the image (`file`): its GUID and age must equal the image's CodeView record. `pdb` is the PDB to keep. A PDB beside the image is found without this.",
            Some(schema::v1::SYMBOLS_ADD),
            Origin::Builtin,
            Box::new(add),
        ));
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

/// Check that the PDB belongs to the image, read it whole, and keep it where
/// the lookup finds it.
fn add(args: &Value) -> Response<Value> {
    let (Some(file), Some(pdb)) = (str_arg(args, "file"), str_arg(args, "pdb")) else {
        return Response::error("missing-argument", "'file' (the image) and 'pdb' (the PDB to keep) are both required");
    };
    let image = match StaticImage::load(Path::new(file)) {
        Ok(image) => image,
        Err(e) => return Response::error("load-failed", e.to_string()),
    };
    let Some((wanted, name)) = pdb_syms::wanted(&image).filter(|(_, name)| !name.is_empty()) else {
        return Response::error("no-codeview", "the image names no PDB (it has no CodeView record), so no PDB can be matched to it");
    };
    let bytes = match std::fs::read(pdb) {
        Ok(bytes) => bytes,
        Err(e) => return Response::error("pdb-unreadable", format!("{pdb}: {e}")),
    };
    let found = match n0xis_pdb::identity(&bytes) {
        Ok(found) => found,
        Err(e) => return Response::error("pdb-unreadable", format!("{pdb}: {e}")),
    };
    if found != wanted {
        return Response::error(
            "pdb-mismatch",
            format!(
                "{pdb} is the PDB of another build: GUID {} age {}, where the image names GUID {} age {}",
                found.guid, found.age, wanted.guid, wanted.age
            ),
        );
    }
    // Read whole before it is kept: one whose identity reads and whose
    // functions do not is not kept.
    let contents = match n0xis_pdb::read(&bytes) {
        Ok(contents) => contents,
        Err(e) => return Response::error("pdb-unreadable", format!("{pdb}: {e}")),
    };
    let root = match n0xis_project::resolve() {
        Ok(root) => root,
        Err(e) => return Response::error("project-unresolved", e.to_string()),
    };
    let dest = pdb_syms::store_path(&root.symbols_dir(), &name, &wanted);
    let kept = dest.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| {
        let partial = dest.with_extension("partial");
        std::fs::write(&partial, &bytes)?;
        std::fs::rename(&partial, &dest)
    });
    if let Err(e) = kept {
        return Response::error("store-failed", format!("{}: {e}", dest.display()));
    }
    pdb_syms::forget();
    Response::success(
        schema::v1::SYMBOLS_ADD,
        json!({
            "stored": dest.display().to_string(),
            "is_local": root.is_local,
            "guid": wanted.guid.to_string(),
            "age": wanted.age,
            "functions": contents.functions.len(),
            "with_length": contents.functions.iter().filter(|f| f.len.is_some()).count(),
            "skipped": {
                "streams": contents.skipped.streams,
                "unplaced": contents.skipped.unplaced,
                "names": contents.skipped.names,
            },
        }),
    )
}
