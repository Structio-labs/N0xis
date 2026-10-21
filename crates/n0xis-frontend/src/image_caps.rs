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
