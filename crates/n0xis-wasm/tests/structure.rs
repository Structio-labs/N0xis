// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **Every structural rule of the binary format is checked, and a break is a
//! typed answer**: modules planted byte by byte (`common/planted.rs`), each
//! breaking one rule or none, with the answer stated before the reader runs.
//! The oracle test asks wasm-tools and wabt about the same bytes.

mod common;

use common::planted::{self, Expect};
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
