// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Questions asked of an image whatever its format, as capabilities: one
//! command per question, never one per container (IMAGE_FORMATS.md §7
//! decision 4). Each answer is the format seam's own ([`n0xis_sources::Image`]),
//! so a format that implements the trait answers here without a line of its
//! own.

use n0xis_contracts::{Response, schema};
use serde_json::{Value, json};

use crate::registry::{Capability, Origin, Plugin, Registry};
use crate::source::{SourceSpec, Src, resolve};

pub struct ImageTools;

impl Plugin for ImageTools {
    fn name(&self) -> &str {
        "n0xis.image"
    }

    fn register(&self, reg: &mut Registry) {
        reg.add(Capability::new(
            "imports",
            "What an image file (`file`) needs from other images: its libraries in the order it states them, and each imported \
             name with the library it is attributed to and how it is reached (a slot, a stub, or an index). `imports.not_read` with \
             the reason where the table was not read: a PE that only a permissive parse opened, a PE with a delay-load import \
             table (which is not read), and an ELF that is not an executable or a shared object (a relocatable object). Where it \
             is read in part, it says which part: a library's `references_not_read` (a PE lookup table holding more entries than \
             its parser returned) and the image's `reach_not_read` (PLT stubs of a machine whose stubs are not decoded). An ELF's \
             binding is flat, and a library it names for a symbol is informative.",
            Some(schema::v1::IMPORTS),
            Origin::Builtin,
            Box::new(imports),
        ));
    }
}

fn imports(args: &Value) -> Response<Value> {
    let spec = SourceSpec {
        pid: args.get("pid").and_then(Value::as_u64).map(|v| v as u32),
        file: args.get("file").and_then(Value::as_str),
        snapshot: args.get("snapshot").and_then(Value::as_str),
        remote_cmd: args.get("remote_cmd").and_then(Value::as_str),
        ..Default::default()
    };
    let resolved = match resolve(spec) {
        Ok(r) => r,
        Err((c, m)) => return Response::error(&c, m),
    };
    // A live process, a snapshot or a remote agent is read through the
    // memory seam only; its modules are not opened as images yet.
    let Src::Static(img) = &resolved.src else {
        return Response::error("not-an-image", "imports are read from an image file (`file`); this source is not one");
    };
    match serde_json::to_value(img.image().imports()) {
        Ok(imports) => Response::success(schema::v1::IMPORTS, json!({ "format": img.format().name(), "imports": imports })).with_source(resolved.label),
        Err(e) => Response::error("serialize", e.to_string()),
    }
}

/// `profile` of a WebAssembly module, or `None` for an image of another
/// format: the format-neutral profile of every image, assembled from the
/// [`n0xis_sources::Image`] answers the way an ELF's is, and beside it what
/// only a module states — its index spaces, memories, tables, segments and
/// start function — in a `module` block.
///
/// **What the image profile shows that has no meaning for a module**, decided
/// here and stated so: `module_base` is 0 and `image_end` the module's length
/// (its positions are its own offsets); `pdata_present`/`pdata_functions`,
/// `thunk_count` and `detoured_exports` answer `false`/0/empty (a module has
/// no unwind table, and an export names a function by its index, so none is a
/// thunk or a detour); `folded` lists each function exported under more than
/// one name, as it lists a native image's exports that share an address — in
/// a module, one function index with several names, with the index beside
/// it; a section's
/// `virtual_size` and `raw_size` are both its contents' size; and the
/// `exports` listed there are the functions the module defines and exports,
/// at their bodies — every export, of every kind and with its index, is the
/// module block's.
pub fn wasm_profile(img: &n0xis_sources::ImageSource, with_exports: bool) -> Option<Value> {
    let n0xis_sources::FormatTables::Wasm(module) = img.tables() else { return None };
    let m = module.module();
    let image = img.image();
    let sections: Vec<n0xis_core::SectionInfo> = image
        .sections()
        .iter()
        .map(|s| n0xis_core::SectionInfo {
            name: s.name.clone(),
            va: s.va,
            virtual_size: s.size.min(u64::from(u32::MAX)) as u32,
            raw_size: s.file_size.min(u64::from(u32::MAX)) as u32,
            executable: s.executable,
        })
        .collect();
    let exports = image.exports().read().cloned().unwrap_or_default();
    let code_exports: Vec<n0xis_core::ExportInfo> = exports
        .iter()
        .filter_map(|e| match (&e.name, &e.target) {
            (Some(name), n0xis_sources::ExportTo::Function { index, body: Some(va) }) => Some(n0xis_core::ExportInfo {
                name: name.clone(),
                va: *va,
                index: Some(*index),
                forwarder: None,
                thunk_target: None,
                thunk_kind: None,
            }),
            _ => None,
        })
        .collect();
    let profile = n0xis_core::assemble_profile(img.image_base(), img.machine(), sections, code_exports, None, with_exports);
    // The native advisories are not asked: they read `.text`, `.pdata` and
    // engine export prefixes, none of which a module's code window or its
    // commands depend on (the code window of a module is its code section).
    let advisories = vec![n0xis_core::Advisory {
        command: "decomp pseudo, ir, function summary/typeflow/layout/trace/noreturn, analyze, const identify, bindings list, sig gen".into(),
        verdict: "ineffective".into(),
        reason: format!("each refuses this module with `not-lifted`: {}", n0xis_arch::WASM_NOT_LIFTED),
    }];

    let (memories, segments) = match &image.machine().address_model {
        n0xis_sources::AddressModel::LinearMemories { memories, segments } => (memories.clone(), segments.clone()),
        n0xis_sources::AddressModel::Native(_) => (Vec::new(), Vec::new()),
    };
    let tables: Vec<Value> = m
        .tables()
        .iter()
        .enumerate()
        .map(|(i, t)| {
            json!({
                "index": i,
                "element": t.ty.element.to_string(),
                "address": format!("{:?}", t.ty.limits.address).to_lowercase(),
                "min": t.ty.limits.min,
                "max": t.ty.limits.max,
                "import": match t.origin { n0xis_wasm::TableOrigin::Imported { import } => Some(import), n0xis_wasm::TableOrigin::Defined { .. } => None },
            })
        })
        .collect();
    let start = m.start().map(|f| json!({ "index": f.0, "body": m.body_start(f).map(|b| n0xis_contracts::Va(b as u64)) }));
    let customs: Vec<&str> = m.custom_sections().map(|(name, _)| name).collect();
    let imports = serde_json::to_value(image.imports()).unwrap_or(Value::Null);
    let findings: Vec<Value> = image.findings().iter().map(|f| serde_json::to_value(f).unwrap_or(Value::Null)).collect();
    Some(json!({
        "image": profile,
        "module": {
            "identity": module.identity(),
            "linkage": format!("{:?}", img.linkage()),
            "functions": { "imported": m.imported_functions(), "defined": m.bodies().len() },
            "start": start,
            "imports": imports,
            "exports": exports,
            "memories": memories,
            "tables": tables,
            "globals": m.globals().len(),
            "tags": m.tags().len(),
            "data_segments": segments,
            "element_segments": module.element_segments(),
            "custom_sections": customs,
            "findings": findings,
        },
        "advisories": advisories,
    }))
}
