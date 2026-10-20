// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Every structural rule of the binary format is checked, and a break is a
//! typed answer**: modules planted byte by byte (`common/planted.rs`), each
//! breaking one rule or none, with the answer stated before the reader runs.
//! The oracle test asks three validators about the same bytes (wasm-tools,
//! wabt and V8), and `wasm-tools print` whether they decode.

mod common;

use std::collections::BTreeMap;

use common::planted::{self, Expect, Tool};
use n0xis_wasm::{Error, Finding, FuncIdx, Instr};

#[test]
fn each_planted_module_gets_the_answer_stated_for_it() {
    let mut wrong = Vec::new();
    let cases = planted::cases();
    for case in &cases {
        let read = n0xis_wasm::read(&case.bytes);
        let answer = match (&case.expect, &read) {
            (Expect::Reads, Ok(m)) if m.findings().is_empty() => continue,
            (Expect::Refused(p), Err(Error::Unreadable { problem, .. })) if problem == p => continue,
            (Expect::Body(p), Ok(m)) => match m.findings() {
                [Finding::Body { func: FuncIdx(0), error: Error::Unreadable { problem, .. } }] if problem == p => {
                    // `body` gives the same error `read` recorded.
                    match m.body(FuncIdx(0)) {
                        Some(Err(Error::Unreadable { problem, .. })) if problem == *p => continue,
                        other => format!("read found {p:?} and body answered {other:?}"),
                    }
                }
                other => format!("{other:?}"),
            },
            (Expect::Name(p), Ok(m)) if m.findings() == [Finding::Name(p.clone())] => continue,
            (_, Ok(m)) => format!("read, with findings {:?}", m.findings()),
            (_, Err(e)) => format!("{e}"),
        };
        wrong.push(format!("{}: {answer}", case.name));
    }
    assert!(wrong.is_empty(), "{} of {} planted modules answered otherwise:\n{}", wrong.len(), cases.len(), wrong.join("\n"));
    eprintln!("{} planted modules, each answered as stated", cases.len());
}

/// A case states two answers, the reader's ([`Expect`]) and the independent
/// validators' ([`Tool`]), and the oracle test checks only the second against
/// the tools. So the two must fit each other, or a reader defect stated as the
/// expected answer passes both tests: the reader refuses (a module or a body)
/// only what is malformed, or well formed only in a proposal it does not read,
/// and reads, with or without a finding about the name section, only what is
/// well formed, valid or not. Every pair is written out, so a new variant of
/// either must be placed.
#[test]
fn each_planted_answer_for_the_reader_fits_the_one_for_the_validators() {
    let cases = planted::cases();
    let misfits: Vec<String> = cases
        .iter()
        .filter(|case| {
            let fits = match (&case.expect, case.tool) {
                (Expect::Refused(_) | Expect::Body(_), Tool::Rejects | Tool::AcceptsOutsideScope) => true,
                (Expect::Refused(_) | Expect::Body(_), Tool::Accepts | Tool::RejectsByValidation) => false,
                (Expect::Reads | Expect::Name(_), Tool::Accepts | Tool::RejectsByValidation) => true,
                (Expect::Reads | Expect::Name(_), Tool::Rejects | Tool::AcceptsOutsideScope) => false,
            };
            !fits
        })
        .map(|case| format!("{}: the reader {}, and the validators are stated to answer {:?}", case.name, stated(&case.expect), case.tool))
        .collect();
    assert!(misfits.is_empty(), "{} of {} planted cases state answers that do not fit each other:\n{}", misfits.len(), cases.len(), misfits.join("\n"));
}

fn stated(expect: &Expect) -> String {
    match expect {
        Expect::Reads => "reads it".into(),
        Expect::Refused(p) => format!("refuses it ({p:?})"),
        Expect::Body(p) => format!("refuses its body ({p:?})"),
        Expect::Name(p) => format!("reads it, with a finding about the name section ({p:?})"),
    }
}

/// A case is known by its name: the oracle test's settled differences name
/// the case they are about, and a second case of the same name would be
/// settled by an entry written for the first.
#[test]
fn each_planted_case_has_its_own_name() {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for case in planted::cases() {
        *seen.entry(case.name).or_insert(0) += 1;
    }
    let repeated: Vec<_> = seen.iter().filter(|(_, n)| **n > 1).collect();
    assert!(repeated.is_empty(), "planted case names used more than once (name, times): {repeated:?}");
}

/// The values at the edges decode to the values planted.
#[test]
fn edge_values_decode_to_the_values_planted() {
    let first = |bytes: &[u8]| -> Instr {
        let m = n0xis_wasm::read(bytes).expect("reads");
        m.body(FuncIdx(0)).unwrap().unwrap().instructions[0].instr.clone()
    };
    assert_eq!(first(&planted::with_body(&[0x41, 0xff, 0xff, 0xff, 0xff, 0x07, 0x1a, 0x0b])), Instr::I32Const(i32::MAX));
    assert_eq!(first(&planted::with_body(&[0x41, 0x80, 0x80, 0x80, 0x80, 0x78, 0x1a, 0x0b])), Instr::I32Const(i32::MIN));
    let i64_min = [0x42, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f, 0x1a, 0x0b];
    assert_eq!(first(&planted::with_body(&i64_min)), Instr::I64Const(i64::MIN));
    // A padded 0xFC code and a padded call index are the same instruction.
    let m = n0xis_wasm::read(&planted::with_body(&[0x43, 0, 0, 0, 0, 0xfc, 0x80, 0x00, 0x1a, 0x0b])).unwrap();
    assert_eq!(m.body(FuncIdx(0)).unwrap().unwrap().instructions[1].instr, Instr::I32TruncSatF32S);
    let m = n0xis_wasm::read(&planted::with_body(&[0x10, 0x80, 0x80, 0x80, 0x80, 0x00, 0x0b])).unwrap();
    assert_eq!(m.body(FuncIdx(0)).unwrap().unwrap().instructions[0].instr, Instr::Call(FuncIdx(0)));
}

/// `br_on_cast`'s flags byte decides each side's nullability: 3 sets both.
#[test]
fn br_on_cast_with_flags_3_casts_a_nullable_reference_to_a_nullable_one() {
    use n0xis_wasm::{AbsHeapType, CastBranch, HeapType, LabelIdx, RefType};
    let bytes = planted::with_gc_body(&[0x02, 0x6e, 0xd0, 0x6e, 0xfb, 0x18, 0x03, 0x00, 0x6e, 0x6e, 0x0b, 0x1a, 0x0b]);
    let m = n0xis_wasm::read(&bytes).expect("reads");
    let instr = m.body(FuncIdx(0)).unwrap().unwrap().instructions[2].instr.clone();
    let anyref = RefType { nullable: true, heap: HeapType::Abstract(AbsHeapType::Any) };
    assert_eq!(instr, Instr::BrOnCast(CastBranch { label: LabelIdx(0), from: anyref, to: anyref }));
    assert_eq!(instr.to_string(), "br_on_cast 0 anyref anyref");
}

/// A concrete heap type is a type index as an s33, padded or not.
#[test]
fn a_concrete_heap_type_is_a_type_index_padded_or_not() {
    use n0xis_wasm::{HeapType, RefType, TypeIdx, ValType};
    let param = |bytes: &[u8]| -> ValType {
        let m = n0xis_wasm::read(&planted::one_type(bytes)).expect("reads");
        m.func_type(TypeIdx(0)).expect("a function type").params[0]
    };
    let nullable = param(&[0x60, 0x01, 0x63, 0x05, 0x00]);
    assert_eq!(nullable, ValType::Ref(RefType { nullable: true, heap: HeapType::Concrete(TypeIdx(5)) }));
    assert_eq!(nullable.to_string(), "(ref null 5)");
    let padded = param(&[0x60, 0x01, 0x64, 0x85, 0x80, 0x80, 0x80, 0x00, 0x00]);
    assert_eq!(padded, ValType::Ref(RefType { nullable: false, heap: HeapType::Concrete(TypeIdx(5)) }));
    assert_eq!(padded.to_string(), "(ref 5)");
}

/// A recursion group has only the format's two shapes: a bare subtype is the
/// group of exactly that one type, and an explicit `rec` holds zero or more,
/// one included.
#[test]
fn a_bare_subtype_is_a_single_group_and_an_explicit_rec_holds_zero_or_more() {
    use n0xis_wasm::{RecGroup, TypeIdx};
    let groups = |entry: &[u8]| n0xis_wasm::read(&planted::one_type(entry)).expect("reads").rec_groups().to_vec();
    assert_eq!(groups(&[0x5f, 0x00]), [RecGroup::Single(TypeIdx(0))], "a bare subtype");
    assert_eq!(groups(&[0x4e, 0x00]), [RecGroup::Rec(0..0)], "(rec)");
    assert_eq!(groups(&[0x4e, 0x01, 0x5f, 0x00]), [RecGroup::Rec(0..1)], "an explicit group of one");
    assert_eq!(RecGroup::Single(TypeIdx(4)).types(), 4..5);
    assert!(!RecGroup::Single(TypeIdx(4)).is_explicit());
    assert!(RecGroup::Rec(0..0).is_explicit());

    // gc.wat states `(rec)`, a `rec` of three, `(rec (type $empty ...))`, then
    // 17 bare types, 4 to 20.
    let gc = common::module("gc");
    let stated: Vec<RecGroup> =
        [RecGroup::Rec(0..0), RecGroup::Rec(0..3), RecGroup::Rec(3..4)].into_iter().chain((4..=20).map(|t| RecGroup::Single(TypeIdx(t)))).collect();
    assert_eq!(gc.rec_groups(), stated);
}

/// Subsection 11 names tags.
#[test]
fn tag_names_land_in_the_tag_map() {
    use planted::*;
    let bytes = module(&[types(), functions(), tag_section(), code(&[0], &[0x0b]), names(&[(11, name_map(&[(0, b"t")]))])]);
    let m = n0xis_wasm::read(&bytes).expect("reads");
    assert!(m.findings().is_empty(), "{:?}", m.findings());
    let names = m.names().expect("a name section");
    assert_eq!(names.tags.get(&n0xis_wasm::TagIdx(0)).map(String::as_str), Some("t"));
}

/// Subsection 10 names the fields of structure types, by type, then field.
#[test]
fn field_names_land_in_the_field_map() {
    use n0xis_wasm::{FieldIdx, TypeIdx};
    use planted::*;
    // Type 0 `(struct (field i32))`, its field 0 named "x".
    let fields = vector(&[[vec![0], name_map(&[(0, b"x")])].concat()]);
    let bytes = module(&[section(1, &vector(&[vec![0x5f, 0x01, 0x7f, 0x00]])), names(&[(10, fields)])]);
    let m = n0xis_wasm::read(&bytes).expect("reads");
    assert!(m.findings().is_empty(), "{:?}", m.findings());
    let names = m.names().expect("a name section");
    let field = names.fields.get(&TypeIdx(0)).and_then(|f| f.get(&FieldIdx(0)));
    assert_eq!(field.map(String::as_str), Some("x"));
}

/// A name subsection that cannot be read is left out whole, and the ones
/// around it are kept.
#[test]
fn a_broken_name_subsection_is_left_out_and_its_neighbours_kept() {
    use planted::*;
    let bad_names = vector(&[[vec![0], vec![1, 0xff]].concat()]);
    let bytes = module(&[types(), functions(), code(&[0], &[0x0b]), names(&[(0, name(b"kept")), (1, bad_names), (7, vector(&[[vec![0], name(b"g")].concat()]))])]);
    let m = n0xis_wasm::read(&bytes).expect("a name section never refuses a module");
    let names = m.names().expect("the section was read");
    assert_eq!(names.module.as_deref(), Some("kept"));
    assert!(names.functions.is_empty(), "the broken subsection is left out whole");
    assert_eq!(names.globals.get(&n0xis_wasm::GlobalIdx(0)).map(String::as_str), Some("g"), "the one after it is read");
    assert!(
        matches!(m.findings(), [Finding::Name(n0xis_wasm::NameProblem::Subsection { id: 1, error: Error::Unreadable { problem: n0xis_wasm::Problem::Utf8, .. } })]),
        "{:?}",
        m.findings()
    );
}

/// A module with no name section says so, which is not an empty one.
#[test]
fn no_name_section_is_none_and_an_empty_one_is_some() {
    use planted::*;
    let without = n0xis_wasm::read(&with_body(&[0x0b])).unwrap();
    assert!(without.names().is_none());
    let empty = n0xis_wasm::read(&module(&[types(), functions(), code(&[0], &[0x0b]), names(&[])])).unwrap();
    assert_eq!(empty.names(), Some(&n0xis_wasm::Names::default()));
}
