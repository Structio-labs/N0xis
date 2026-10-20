// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! **The recordings the default tests compare against are what the tools say
//! today, and the planted modules' answers are what independent validators
//! give.** A local instrument, not a CI gate (`--features oracle`): it runs
//! clang, wasm-ld, wasm-tools, wabt and node from this machine, whose versions
//! a CI runner does not pin. A missing tool fails the test; it never skips.
//!
//! - `fixtures/build.sh` is run into a fresh directory, rebuilding every
//!   fixture from its source and recording every tool output again. The files
//!   it must make are derived from [`common::FIXTURES`] and
//!   [`common::WABT_REFUSES`] (82 today); it must make exactly those, each
//!   must equal the one checked in, and the fixtures directory must hold no
//!   other recording. When a tool's version changes what it prints, run
//!   `sh fixtures/build.sh` and look at the diff. The script runs traced, and
//!   every source in the directory must be an argument of a command it ran
//!   that consumes a source of its kind ([`CONSUMERS`]): a `.c` file of
//!   clang's, a `.wat` file of `wasm-tools parse`'s.
//! - Every planted module (`common/planted.rs`) is given to three validators,
//!   with every feature they have on: `wasm-tools validate`, wabt's
//!   `wasm-validate` and V8 (`fixtures/v8dis.mjs --validate`, which compiles
//!   it with `new WebAssembly.Module`). A module stated to break a rule must be
//!   rejected, and one stated to be well formed (or well formed in a proposal
//!   this crate does not read) accepted. A verdict that differs is a failure
//!   unless [`SETTLED`] names it with the third source that decides it.
//! - A validator is asked only about the cases whose proposals it implements
//!   ([`row`] is the one table of which implements which): a validator that
//!   cannot read a recursion group says nothing about a rule planted inside
//!   one, whichever way it answers. The verdicts asked and not asked are
//!   counted per validator and proposal and must be exactly the stated ones
//!   ([`stated_asks`]), since a case's own `needs` is what withdraws a verdict;
//!   a verdict not asked is never a pass. And the table is itself checked: a
//!   validator the table says lacks a proposal must refuse every module of it
//!   that is stated to be well formed, so a limitation that a new version
//!   lifts, even in part, fails here instead of staying recorded; and each of
//!   those refusals must contain a refusal the table quotes for the proposal,
//!   so that a module refused for a reason of its own does not confirm the
//!   lack, and every quote must be drawn by some case or be listed in
//!   [`QUOTED_NOT_DRAWN`]. Those answers are evidence about the table only;
//!   they are not counted as verdicts on the cases.
//! - The same modules are given to `wasm-tools print`, which decodes without
//!   validating: a case stated to be malformed must fail to print and every
//!   other case must print, so the line between malformed and invalid, which
//!   no validator draws, is checked too ([`SETTLED_DECODE`] for differences).
//! - A tool failure never reads as a verdict ([`verdict`]): every judge must
//!   first accept the minimal module and refuse one with no magic
//!   ([`check_controls`]), a file is looked for before a judge is asked about
//!   it, and an exit status other than 0 or 1, or a refusal that says nothing
//!   on stderr, fails the test.
//!
//! Known and not fixed:
//! - The trace check splits each `sh -x` line on whitespace and trims quotes,
//!   so a source path with a space in it is never matched (a failure, not a
//!   pass), and a source fed through a redirection or a pipe reads as not
//!   read. It checks that the consumer was given the source, not that what
//!   the consumer made from it is a compared recording: the comparison of
//!   every recording does that for the outputs it lists.
//! - A quote is a substring: a short one (`got -0x30`) could be contained in a
//!   refusal given for another reason. Only refusals of cases stated to be
//!   well formed are compared with the quotes; a lacked proposal's malformed
//!   or invalid case is neither asked nor compared.
//! - The verdict counts ([`stated_asks`]) and [`DECODES_ASKED`] are the
//!   test's own measurement, restated by hand when they move.
#![cfg(feature = "oracle")]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use common::planted::{self, Proposal, Tool};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("n0xis-wasm-oracle-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// Every file `build.sh` records, by name: for each fixture its module,
/// `wasm-tools print`'s text and V8's disassembly, then wabt's three
/// recordings, or for a fixture wabt cannot read its refusal in their place.
fn recorded_files() -> Vec<String> {
    let mut files = Vec::new();
    for stem in common::FIXTURES {
        let wabt: &[&str] = if common::wabt_reads(stem) { &["headers.txt", "details.txt", "disassembly.txt"] } else { &["wabt-refuses.txt"] };
        for suffix in ["wasm", "print.txt", "v8.txt"].iter().chain(wabt) {
            files.push(format!("{stem}.{suffix}"));
        }
    }
    files
}

/// The kinds of file in the fixtures directory that `build.sh` reads, and the
/// command that consumes each: the words a traced command line must begin
/// with for its arguments to count as read. The sources of the modules
/// (clang for C, clang++ for C++, `wasm-tools parse` for the text format), the
/// V8 script (node), and a shell script (sh). `build.sh` itself is the one
/// `.sh` file, and the test runs it.
const CONSUMERS: [(&str, &[&str]); 5] = [(".wat", &["wasm-tools", "parse"]), (".c", &["clang"]), (".cpp", &["clang++"]), (".sh", &["sh"]), (".mjs", &["node"])];

/// The command that consumes a source file, by its kind; `None` for a file
/// that is no source `build.sh` reads.
fn consumer(file: &str) -> Option<&'static [&'static str]> {
    CONSUMERS.iter().find(|(ext, _)| file.ends_with(ext)).map(|(_, command)| *command)
}

/// The files of the fixtures directory that are sources, not recordings:
/// what `build.sh` reads, and the notes beside it.
fn is_source(file: &str) -> bool {
    consumer(file).is_some() || file.ends_with(".md")
}

/// Whether the trace `sh -x` wrote has a command beginning with the words of
/// `command` that names `dir/file` as one of its later arguments. The trace
/// line of a command is `+` (one more per nested substitution), a space, and
/// the words, each quoted when it needs to be; what a redirection reads does
/// not appear in it, so a source read only through `<` is not read here.
fn trace_consumes(trace: &str, dir: &Path, file: &str, command: &[&str]) -> bool {
    let dir = dir.canonicalize().unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    let is_it = |arg: &str| {
        let path = Path::new(arg.trim_matches(|c| c == '\'' || c == '"'));
        path.file_name().is_some_and(|name| name == file) && path.parent().and_then(|parent| parent.canonicalize().ok()).is_some_and(|parent| parent == dir)
    };
    trace.lines().filter(|line| line.starts_with('+')).filter_map(|line| line.trim_start_matches('+').strip_prefix(' ')).any(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        words.len() > command.len() && words[..command.len()] == *command && words[command.len()..].iter().any(|arg| is_it(arg))
    })
}

fn file_names(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("a directory entry").file_name().into_string().expect("a UTF-8 file name"))
        .collect()
}

#[test]
fn the_recordings_are_what_the_sources_and_the_tools_give_today() {
    let files = recorded_files();
    // 14 fixtures, each with its module, print and V8 recordings (42); the 13
    // wabt reads with its three (39); gc, which it does not, with its refusal.
    assert_eq!(files.len(), 82, "the recorded files: {files:?}");
    let expected: BTreeSet<String> = files.iter().cloned().collect();
    assert_eq!(expected.len(), files.len(), "a file listed twice");

    let out = scratch("rebuild");
    // Traced, so that what build.sh read can be checked below.
    let run = Command::new("sh").arg("-x").arg(common::dir().join("build.sh")).arg(&out).output().expect("sh runs");
    assert!(
        run.status.success(),
        "build.sh failed (a missing tool is a failure here):\n{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    // build.sh makes exactly these: a recording it makes and nothing compares
    // would be an answer no one reads, and one it no longer makes would be
    // compared against a file left over from an older build.
    let made = file_names(&out);
    let not_made: Vec<_> = expected.difference(&made).collect();
    let not_listed: Vec<_> = made.difference(&expected).collect();
    let checked_in = file_names(&common::dir());
    let left_over: Vec<_> = checked_in.iter().filter(|f| !is_source(f) && !expected.contains(*f)).collect();
    let mut differ = Vec::new();
    for file in files.iter().filter(|f| made.contains(*f)) {
        let fresh = std::fs::read(out.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let recorded = std::fs::read(common::dir().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        if fresh != recorded {
            differ.push(file);
        }
    }
    let _ = std::fs::remove_dir_all(&out);
    // Every source in the directory is one build.sh reads, as an argument of
    // a command it ran that consumes a source of that kind: a source it does
    // not read would sit beside the fixtures looking like the origin of one,
    // with nothing checking that it is, and one it only names (a `test -f`,
    // an `echo`, a copy compiled instead) is not read either. Read from what
    // the script did, not from its text, which names the `.wat` files only as
    // `$name.wat` in a loop. The script itself is what the test runs.
    let trace = String::from_utf8_lossy(&run.stderr);
    let unread: Vec<_> = checked_in
        .iter()
        .filter(|f| f.as_str() != "build.sh")
        .filter_map(|f| consumer(f).map(|command| (f, command)))
        .filter(|(f, command)| !trace_consumes(&trace, &common::dir(), f, command))
        .map(|(f, command)| format!("{f} (no `{}` names it)", command.join(" ")))
        .collect();
    assert!(not_made.is_empty() && not_listed.is_empty(), "build.sh did not make {not_made:?}, and made {not_listed:?} that is not listed");
    assert!(left_over.is_empty(), "files in the fixtures directory build.sh no longer records: {left_over:?}");
    assert!(differ.is_empty(), "rebuilt or re-recorded differently (run build.sh and read the diff): {differ:?}");
    assert!(unread.is_empty(), "sources in the fixtures directory build.sh does not read: {unread:?}");
    let sources = checked_in.iter().filter(|f| consumer(f).is_some()).count();
    eprintln!(
        "{} files rebuilt and re-recorded by build.sh, each equal to the one checked in; {sources} sources, each an argument of the \
         command that consumes its kind (build.sh itself is the script run)",
        files.len()
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Validator {
    WasmTools,
    Wabt,
    V8,
}

impl Validator {
    const ALL: [Validator; 3] = [Validator::WasmTools, Validator::Wabt, Validator::V8];

    fn name(self) -> &'static str {
        match self {
            Validator::WasmTools => "wasm-tools",
            Validator::Wabt => "wasm-validate",
            Validator::V8 => "V8",
        }
    }

    /// Whether this validator accepts the module at `path`, or refuses it
    /// with this on stderr; see [`verdict`] for what is not a verdict.
    fn judge(self, path: &Path) -> Result<(), String> {
        let v8dis = common::dir().join("v8dis.mjs").display().to_string();
        let (program, args): (&str, Vec<&str>) = match self {
            Validator::WasmTools => ("wasm-tools", vec!["validate", "--features", "all"]),
            // The format says an error in a custom section's data, or its
            // placement, must not invalidate the module; wabt applies that
            // only when asked.
            Validator::Wabt => ("wasm-validate", vec!["--enable-all", "--ignore-custom-section-errors"]),
            Validator::V8 => ("node", vec![v8dis.as_str(), "--validate"]),
        };
        verdict(self.name(), program, &args, path)
    }
}

/// `wasm-tools print`: whether it decodes the module at `path`. It prints a
/// module without validating it, so it is the judge of the line between a
/// malformed module and an invalid one, which no validator draws.
fn decodes(path: &Path) -> bool {
    verdict(DECODER, "wasm-tools", &["print"], path).is_ok()
}

const DECODER: &str = "wasm-tools print";

/// A judge's answer about the file at `path`: its exit status, 0 yes and 1
/// no, with what it said on stderr. Anything that is not an answer fails the
/// test instead of reading as "no", which on a case stated to be refused would
/// read as agreement:
///
/// - a file that is not there: wasm-tools and wasm-validate both exit 1 on
///   one, with a message, exactly as they refuse a module, so the file is
///   looked for first;
/// - any other status, or a signal: a bad option is wasm-tools' 2, and
///   `v8dis.mjs`'s 2 is a failure of the script itself (a missing file
///   included);
/// - a 1 with nothing on stderr: every judge here says why it refuses.
///
/// A bad option wasm-validate exits 1 on, with a message, and so does node on
/// a script it cannot find: indistinguishable here from a refusal, so
/// [`check_controls`] catches them, since such a judge refuses the minimal
/// module.
fn verdict(judge: &str, program: &str, args: &[&str], path: &Path) -> Result<(), String> {
    assert!(path.is_file(), "{judge} was to be asked about {}, which is not a file", path.display());
    let out = Command::new(program)
        .args(args)
        .arg(path)
        .env("LC_ALL", "C")
        .output()
        .unwrap_or_else(|e| panic!("{program} could not run (a missing tool is a failure here): {e}"));
    let failure = |what: &str| -> ! {
        panic!(
            "{judge} gave no verdict on {} ({what}, {}):\n{}{}",
            path.display(),
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    match out.status.code() {
        Some(0) => Ok(()),
        Some(1) if stderr.trim().is_empty() => failure("a refusal that says nothing on stderr"),
        Some(1) => Err(stderr.into_owned()),
        _ => failure("an exit status that is neither 0 nor 1"),
    }
}

/// The two answers every judge must give before it is asked about any case:
/// the planted `minimal` module accepted and `no magic` refused. A judge that
/// does not run as it is called (a bad option, a script that fails, a tool
/// that answers every file the same way) fails here, on its own line, rather
/// than as a wall of verdicts on the cases, or worse, as agreement with every
/// case stated to be refused. wasm-tools reads a file that does not begin
/// with the magic as the text format, so its refusal of `no magic` is a text
/// syntax error ("unexpected character"): still a refusal, which is all the
/// control asks.
fn check_controls(judge: &str, cases: &[planted::Case], dir: &Path, says_yes: impl Fn(&Path) -> bool) {
    for (name, stated, want) in [("minimal", Tool::Accepts, true), ("no magic", Tool::Rejects, false)] {
        let case = cases.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("the control case {name:?} is not planted"));
        assert_eq!(case.tool, stated, "the control case {name:?} is not stated as the control needs it");
        let path = dir.join(format!("control-{}.wasm", name.replace(' ', "-")));
        std::fs::write(&path, &case.bytes).expect("written");
        assert_eq!(says_yes(&path), want, "{judge} fails its control: it {} the {name:?} module", if want { "refuses" } else { "accepts" });
    }
}

/// Whether a validator implements a proposal.
#[derive(Clone, Copy, Debug)]
enum Support {
    Implements,
    /// It does not, and this is what it says when given the proposal's bytes:
    /// each text between backticks is a refusal it gives, quoted, and every
    /// refusal of a well-formed case of the proposal must contain one of them
    /// ([`quoted`]).
    Lacks(&'static str),
}

/// The refusals a [`Support::Lacks`] entry quotes: each text between a pair of
/// backticks. Read from the entry's own words, so that what it says the
/// validator answers and what the answer is compared with are one text.
fn quoted(why: &'static str) -> Vec<&'static str> {
    let parts: Vec<&str> = why.split('`').collect();
    assert!(parts.len() % 2 == 1, "an unpaired backtick in {why:?}");
    let quotes: Vec<&str> = parts.into_iter().skip(1).step_by(2).collect();
    assert!(!quotes.is_empty() && quotes.iter().all(|q| !q.trim().is_empty()), "a lack quotes no refusal: {why:?}");
    quotes
}

/// One row of [`row`]'s table: a field per validator, so that a row cannot
/// leave one out.
struct Row {
    wasm_tools: Support,
    wabt: Support,
    v8: Support,
}

impl Row {
    fn of(&self, validator: Validator) -> Support {
        match validator {
            Validator::WasmTools => self.wasm_tools,
            Validator::Wabt => self.wabt,
            Validator::V8 => self.v8,
        }
    }
}

/// Which validator implements which proposal: the one table, measured on
/// 2026-10-19 with wasm-tools 1.262.0 (`--features all`), wabt 1.0.42
/// (`--enable-all`) and V8 14.6.202.34 (node 26.10.0, no flags), on the
/// planted cases and the fixtures. A proposal is implemented where every
/// fixture using it is accepted (`build.sh` validates each with all three) and
/// the validator's verdicts on the planted cases agree with the stated ones
/// or are [`SETTLED`]; where it is lacking, the quoted refusals are what it
/// says about a module stated to be well formed, and every refusal of such a
/// module must contain one of them ([`quoted`]). The match is exhaustive, so a
/// new proposal must be given a row.
fn row(proposal: Proposal) -> Row {
    use Proposal::*;
    use Support::{Implements as Yes, Lacks};
    let row = |wasm_tools, wabt, v8| Row { wasm_tools, wabt, v8 };
    match proposal {
        MultiMemory => row(Yes, Yes, Yes),
        Memory64 => row(Yes, Yes, Yes),
        TailCall => row(Yes, Yes, Yes),
        RelaxedSimd => row(Yes, Yes, Yes),
        // wabt reads `(ref null x)`, `(ref func)`, `(ref extern)` and the
        // `0x40 0x00` table form (refs.wasm); the heap types beyond those are
        // garbage collection's.
        FunctionReferences => row(Yes, Yes, Yes),
        Gc => row(
            Yes,
            Lacks(
                "wabt reads no recursion group (`unexpected type form (got -0x32)`), no packed field \
                 (`expected valid field type (got -0x8)`), no subtype (`got -0x30`, or for a final one \
                 `got -0x31`), and no heap type past func, extern and exn (`Reference type is limited to \
                 func and extern`), with --enable-all, which turns on its --enable-gc",
            ),
            Yes,
        ),
        Exceptions => row(Yes, Yes, Yes),
        Threads => row(Yes, Yes, Yes),
        LegacyExceptions => row(Yes, Yes, Yes),
        SharedEverythingThreads => row(
            Yes,
            Lacks("wabt refuses the shared heap type 0x65: `Reference type is limited to func and extern`"),
            Lacks("V8 refuses the shared heap type 0x65: `invalid heap type 0x65, enable with --experimental-wasm-shared`"),
        ),
        // wabt checks the rule as well as reading the flag: it refuses a page
        // size of 2^1 or 2^5 bytes ("only page sizes of 1 B or 64 KiB are
        // allowed") and accepts 2^0 and 2^16, as wasm-tools does.
        CustomPageSizes => row(Yes, Yes, Lacks("V8 refuses limits flags bit 3: `invalid memory limits flags 0x8`")),
        // wabt type-checks the instructions as well as reading them: it
        // refuses `i64.add128` over four i32 ("type mismatch in i64.add128,
        // expected [i64, i64, i64, i64]"), as wasm-tools does.
        WideArithmetic => row(Yes, Yes, Lacks("V8 refuses 0xFC 0x13: `invalid numeric opcode: 0xfc13`")),
    }
}

/// Every one of a case's proposals the validator lacks, with why, in the
/// order the case names them: empty when it implements them all, and is
/// asked.
fn lacked(validator: Validator, needs: &[Proposal]) -> Vec<(Proposal, &'static str)> {
    needs
        .iter()
        .filter_map(|p| match row(*p).of(validator) {
            Support::Implements => None,
            Support::Lacks(why) => Some((*p, why)),
        })
        .collect()
}

/// How many planted cases there are; [`stated_asks`] says what each
/// validator is asked about them.
const PLANTED_CASES: usize = 96;

/// For a validator, how many verdicts it is asked about the planted cases
/// and how many it is not, per proposal it lacks (a verdict not asked is
/// counted under the first such proposal the case names). Measured
/// 2026-10-20 with the tools of [`row`].
///
/// A case's `needs` is its own declaration, and nothing else reads it: a case
/// that claims a proposal it does not need withdraws the verdict of every
/// validator that lacks it, silently, and the test still passes. So the
/// counts are exact, and any change to them (a case added, a need added or
/// dropped) fails here and must be looked at. The match is exhaustive, so a
/// new validator must state its own.
fn stated_asks(validator: Validator) -> (usize, &'static [(Proposal, usize)]) {
    use Proposal::*;
    match validator {
        Validator::WasmTools => (96, &[]),
        Validator::Wabt => (83, &[(Gc, 12), (SharedEverythingThreads, 1)]),
        Validator::V8 => (93, &[(SharedEverythingThreads, 1), (CustomPageSizes, 1), (WideArithmetic, 1)]),
    }
}

/// A validator's verdict that differs from the stated one, with the third
/// source that settles it: case, validator, its verdict (accepts?), why.
const SETTLED: &[(&str, Validator, bool, &str)] = &[
    (
        "a name section before the data section",
        Validator::Wabt,
        false,
        "wabt refuses a data section after the name section even when told to ignore custom-section \
         errors. The binary format's own note (Modules, Custom Section) says the placement of a custom \
         section must not invalidate the module, and wasm-tools and V8 accept it.",
    ),
    (
        "catch after catch_all",
        Validator::Wabt,
        true,
        "wabt accepts a `catch` after a `catch_all` in a legacy `try`. The legacy exception handling \
         document's text grammar is `try blocktype instruction* (catch tag_index instruction*)* \
         (catch_all instruction*)? end`, and its prose says \"All `catch` blocks must precede the \
         `catch_all` block, if any\"; wasm-tools (\"`catch` found outside `LegacyTry` block\") and V8 \
         (\"catch after catch-all for try\") refuse it.",
    ),
    (
        "a 32-bit memory bound padded to six bytes",
        Validator::V8,
        false,
        "V8 reads a 32-bit memory's bounds as u32 LEB128 (\"length overflow while decoding initial \
         size\"). The 3.0 binary format (Types, Limits) gives all four limits forms `u64` bounds, \
         `limits ::= 0x00 n:u64 => (i32, [n .. eps]) | ...`, and wasm-tools and wabt accept the padded \
         bound.",
    ),
    (
        "a 32-bit table bound padded to six bytes",
        Validator::V8,
        false,
        "V8 reads a 32-bit table's bounds as u32 LEB128 (\"length overflow while decoding initial \
         size\"). The 3.0 binary format (Types, Limits) gives all four limits forms `u64` bounds, and a \
         table type's limits are those limits; wasm-tools and wabt accept the padded bound.",
    ),
];

/// A refusal [`row`] quotes that no planted case draws, so that the planted
/// answers do not check it, and the probe that draws it instead.
struct NotDrawn {
    validator: Validator,
    proposal: Proposal,
    quote: &'static str,
    /// The one entry of a type section (`planted::one_type`): a module of the
    /// proposal the validator must refuse, saying the quote. Asked by the
    /// test, so the quote rests on an answer, not on this text.
    probe: &'static [u8],
    why: &'static str,
}

/// Every [`NotDrawn`] quote. Exact: a quote drawn by a case, or a new quote no
/// case draws, fails, in the order the table's loop meets them.
const QUOTED_NOT_DRAWN: &[NotDrawn] = &[NotDrawn {
    validator: Validator::Wabt,
    proposal: Proposal::Gc,
    quote: "Reference type is limited to func and extern",
    // `(type (func (param (ref null any))))`.
    probe: &[0x60, 0x01, 0x63, 0x6e, 0x00],
    why: "no planted well-formed case of garbage collection has a heap type past func, extern and exn; \
          measured 2026-10-20 with wabt 1.0.42, the probe gives \"000000f: error: Reference type is limited \
          to func and extern: function param type\"",
}];

/// The well-formed cases of a proposal a validator lacks that it was shown,
/// the ones of them it accepted, by name, and the quotes of the entry
/// ([`quoted`]) its refusals contained.
#[derive(Default)]
struct LackShown {
    shown: Vec<&'static str>,
    accepted: Vec<&'static str>,
    said: BTreeSet<&'static str>,
}

#[test]
fn the_planted_answers_are_the_ones_independent_validators_give() {
    let dir = scratch("planted");
    let cases = planted::cases();
    for validator in Validator::ALL {
        check_controls(validator.name(), &cases, &dir, |path| validator.judge(path).is_ok());
    }
    let mut differ: Vec<(String, Validator, bool)> = Vec::new();
    let mut asked: BTreeMap<Validator, usize> = BTreeMap::new();
    let mut not_asked: BTreeMap<(Validator, Proposal), (usize, &'static str)> = BTreeMap::new();
    // For the table's own check: per lacking pair, the well-formed cases of
    // the proposal the validator was shown, and the ones of them it accepted.
    // A case is shown under every proposal it needs that the validator lacks.
    let mut lack_checked: BTreeMap<(Validator, Proposal), LackShown> = BTreeMap::new();
    // Refusals of a well-formed case of a lacked proposal that contain none of
    // the table's quotes for it.
    let mut unquoted: Vec<String> = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let path = dir.join(format!("case{i}.wasm"));
        std::fs::write(&path, &case.bytes).expect("written");
        let want = matches!(case.tool, Tool::Accepts | Tool::AcceptsOutsideScope);
        for validator in Validator::ALL {
            let lacks = lacked(validator, case.needs);
            if let Some(&(first, why)) = lacks.first() {
                not_asked.entry((validator, first)).or_insert((0, why)).0 += 1;
                if want {
                    let answer = validator.judge(&path);
                    // A refusal confirms a lack only if it is the one the
                    // table quotes: a module refused for a reason of its own
                    // (a mistake in the case, a rule of another proposal)
                    // says nothing about the proposal.
                    if let Err(stderr) = &answer {
                        let all: Vec<&str> = lacks.iter().flat_map(|(_, why)| quoted(why)).collect();
                        if !all.iter().any(|q| stderr.contains(q)) {
                            unquoted.push(format!(
                                "{} on {:?} (needing {:?}) says none of {all:?}:\n{}",
                                validator.name(),
                                case.name,
                                lacks.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
                                stderr.trim_end()
                            ));
                        }
                    }
                    for &(proposal, why) in &lacks {
                        let seen = lack_checked.entry((validator, proposal)).or_default();
                        seen.shown.push(case.name);
                        match &answer {
                            Ok(()) => seen.accepted.push(case.name),
                            Err(stderr) => seen.said.extend(quoted(why).into_iter().filter(|q| stderr.contains(q))),
                        }
                    }
                }
                continue;
            }
            *asked.entry(validator).or_insert(0) += 1;
            let got = validator.judge(&path).is_ok();
            if got != want {
                differ.push((case.name.to_string(), validator, got));
            }
        }
    }

    // Every limitation the table records must still be one, on every case:
    // the validator refuses each module of the proposal that is stated to be
    // well formed. One it accepts is evidence that it reads the proposal, at
    // least that far, and then its verdicts on the cases of it are being
    // thrown away.
    let mut stale = Vec::new();
    let mut unsaid: Vec<(Validator, Proposal, &str)> = Vec::new();
    let planted_proposals: BTreeSet<Proposal> = cases.iter().flat_map(|c| c.needs.iter().copied()).collect();
    for validator in Validator::ALL {
        for &proposal in &planted_proposals {
            if let Support::Lacks(why) = row(proposal).of(validator) {
                match lack_checked.get(&(validator, proposal)) {
                    None => {
                        stale.push(format!("{} lacks {proposal:?}: no case of it is stated to be well formed, so the table is not checked", validator.name()))
                    }
                    Some(LackShown { shown, accepted, .. }) if !accepted.is_empty() => stale.push(format!(
                        "{} lacks {proposal:?}, yet it accepts {} of the {} well-formed cases of it: {accepted:?}",
                        validator.name(),
                        accepted.len(),
                        shown.len()
                    )),
                    // A quote no refusal contains is a message the validator
                    // is recorded to give and no longer gives, or never gave,
                    // unless it is one no planted case can draw.
                    Some(LackShown { said, .. }) => {
                        for quote in quoted(why).into_iter().filter(|q| !said.contains(q)) {
                            unsaid.push((validator, proposal, quote));
                        }
                    }
                }
            }
        }
    }

    // The quotes no case draws, each drawn by its probe instead.
    let mut probes_wrong = Vec::new();
    for (i, n) in QUOTED_NOT_DRAWN.iter().enumerate() {
        let path = dir.join(format!("not-drawn{i}.wasm"));
        std::fs::write(&path, planted::one_type(n.probe)).expect("written");
        let answer = n.validator.judge(&path);
        eprintln!("  quoted and drawn by no case: {} {:?} {:?}, by its probe instead ({}): {answer:?}", n.validator.name(), n.proposal, n.quote, n.why);
        if !answer.as_ref().err().is_some_and(|stderr| stderr.contains(n.quote)) {
            probes_wrong.push(format!("{} on the probe for {:?} does not refuse it saying {:?}: {answer:?}", n.validator.name(), n.proposal, n.quote));
        }
    }

    let settled: Vec<(String, Validator, bool)> = SETTLED.iter().map(|(c, v, got, _)| (c.to_string(), *v, *got)).collect();
    let unsettled: Vec<_> = differ.iter().filter(|d| !settled.contains(d)).collect();
    let gone: Vec<_> = settled.iter().filter(|s| !differ.contains(s)).collect();
    // Kept when a verdict is unsettled, so the bytes can be looked at.
    if unsettled.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    }

    let total_asked: usize = asked.values().sum();
    eprintln!(
        "{} planted modules, {total_asked} verdicts asked ({}), {} differ from the stated one",
        cases.len(),
        Validator::ALL.iter().map(|v| format!("{} {}", v.name(), asked.get(v).copied().unwrap_or(0))).collect::<Vec<_>>().join(", "),
        differ.len()
    );
    let mut counts_differ = Vec::new();
    for validator in Validator::ALL {
        let mine: Vec<_> = not_asked.iter().filter(|((v, _), _)| *v == validator).collect();
        let total: usize = mine.iter().map(|(_, (n, _))| n).sum();
        eprintln!("  not asked of {}: {total}", validator.name());
        for ((_, proposal), (n, why)) in &mine {
            let (shown, accepted) = lack_checked.get(&(validator, *proposal)).map(|l| (l.shown.len(), l.accepted.len())).unwrap_or((0, 0));
            eprintln!("    {n} needing {proposal:?} ({why}); of its {shown} well-formed ones it refuses {}", shown - accepted);
        }
        let got: (usize, Vec<(Proposal, usize)>) = (asked.get(&validator).copied().unwrap_or(0), mine.iter().map(|((_, p), (n, _))| (*p, *n)).collect());
        let (stated_asked, stated_not) = stated_asks(validator);
        if got != (stated_asked, stated_not.to_vec()) {
            counts_differ.push(format!("{}: asked {}, not asked {:?}; stated: asked {stated_asked}, not asked {stated_not:?}", validator.name(), got.0, got.1));
        }
    }

    assert!(unsettled.is_empty(), "verdicts that differ from the stated ones (files in {}):\n{unsettled:#?}", dir.display());
    assert!(gone.is_empty(), "settled differences no longer found (remove them from SETTLED):\n{gone:#?}");
    assert!(stale.is_empty(), "the table of which validator implements which proposal is out of date:\n{}", stale.join("\n"));
    assert!(unquoted.is_empty(), "refusals that do not confirm the lack the table records (the quoted refusal is not what was said):\n{}", unquoted.join("\n"));
    let stated_unsaid: Vec<(Validator, Proposal, &str)> = QUOTED_NOT_DRAWN.iter().map(|n| (n.validator, n.proposal, n.quote)).collect();
    assert_eq!(
        unsaid, stated_unsaid,
        "the table's quoted refusals that no refusal of a planted well-formed case contains are not the ones stated in QUOTED_NOT_DRAWN"
    );
    assert!(probes_wrong.is_empty(), "a quote drawn by no case is not drawn by its probe either:\n{}", probes_wrong.join("\n"));
    assert_eq!(cases.len(), PLANTED_CASES, "the planted cases: a case added or removed changes the verdicts asked; restate them");
    assert!(
        counts_differ.is_empty(),
        "the verdicts asked of each validator are not the ones stated (a case's `needs` withdraws the verdict of every \
         validator that lacks a proposal it names; look at which, then restate them):\n{}",
        counts_differ.join("\n")
    );
}

/// A difference between `wasm-tools print` and a case's stated answer, with
/// the third source that settles it: case, whether it decodes, why. Read
/// 2026-10-20: the specification repository (WebAssembly/spec, main at
/// 340650f2, 2026-10-13) and the threads repository (WebAssembly/threads,
/// main at cc535ada).
const SETTLED_DECODE: &[(&str, bool, &str)] = &[
    (
        "data.drop and no data count",
        true,
        "wasm-tools decodes a data index in code with no data count section and leaves the rule to \
         its validator (\"func 0 failed to validate: data count section required\"). The rule is the \
         binary format's: the 3.0 grammar of a module (5.4-binary.modules.spectec, Bmodule) has the side \
         condition `if (n? =/= eps \\/ $dataidx_funcs(func*) = eps)`, the prose \"it must be present if \
         any data index occurs in the code section\", and the specification's test suite states this \
         very module `assert_malformed` (test/core/binary.wast, \"data.drop requires a data count \
         section\").",
    ),
    (
        "a shared table",
        true,
        "wasm-tools decodes a table's limits flags 0x03 as a shared table, which shared-everything \
         threads defines and wasm-tools implements; with that proposal off it says \"shared tables \
         require the shared-everything-threads proposal\". The threads overview (Spec Changes) encodes \
         limits as 0x00, 0x01 and 0x03 and says \"in this proposal only memories are permitted to be \
         marked as shared\", sending shared tables to the shared-everything follow-up; the 3.0 \
         grammar of limits (5.2-binary.types.spectec, Blimits) has only 0x00, 0x01, 0x04 and 0x05. \
         V8 (\"invalid table limits flags\") and wabt (\"tables may not be shared\") refuse it.",
    ),
    (
        "array.new_data and no data count",
        true,
        "As for `data.drop and no data count`: `$dataidx_funcs` collects the data indices free in the \
         code (1.4-syntax.modules.spectec), and `$free_instr(ARRAY.NEW_DATA typeidx dataidx)` includes \
         its data index (1.3-syntax.instructions.spectec), so the module's side condition applies; \
         wasm-tools leaves it to its validator (\"data count section required\").",
    ),
];

/// The number of planted cases put to `wasm-tools print`: those whose every
/// proposal wasm-tools implements ([`row`]). Measured 2026-10-20.
const DECODES_ASKED: usize = 96;

/// The line between a malformed module and an invalid one is the line this
/// crate stands on: it refuses the first and reads the second. The validators
/// refuse both alike, so none of them checks that a case stated `Rejects`
/// (malformed) is not merely invalid, or that one stated `RejectsByValidation`
/// is not malformed. `wasm-tools print` decodes without validating, so it
/// draws the line: a case stated `Rejects` must fail to print, and every
/// other case (`Accepts`, `RejectsByValidation`, `AcceptsOutsideScope`) must
/// print, for every case whose proposals wasm-tools implements.
#[test]
fn the_planted_malformed_modules_are_the_ones_wasm_tools_cannot_decode() {
    let dir = scratch("decode");
    let cases = planted::cases();
    check_controls(DECODER, &cases, &dir, decodes);
    let mut differ: Vec<(String, bool)> = Vec::new();
    let mut asked = 0;
    for (i, case) in cases.iter().enumerate() {
        if !lacked(Validator::WasmTools, case.needs).is_empty() {
            continue;
        }
        let path = dir.join(format!("case{i}.wasm"));
        std::fs::write(&path, &case.bytes).expect("written");
        asked += 1;
        let want = case.tool != Tool::Rejects;
        let got = decodes(&path);
        if got != want {
            differ.push((case.name.to_string(), got));
        }
    }
    let settled: Vec<(String, bool)> = SETTLED_DECODE.iter().map(|(c, got, _)| (c.to_string(), *got)).collect();
    let unsettled: Vec<_> = differ.iter().filter(|d| !settled.contains(d)).collect();
    let gone: Vec<_> = settled.iter().filter(|s| !differ.contains(s)).collect();
    if unsettled.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    eprintln!("{} planted modules, {asked} put to {DECODER}, {} differ from the stated one", cases.len(), differ.len());
    assert!(unsettled.is_empty(), "{DECODER} decodes otherwise than stated (true: it prints; files in {}):\n{unsettled:#?}", dir.display());
    assert!(gone.is_empty(), "settled differences no longer found (remove them from SETTLED_DECODE):\n{gone:#?}");
    assert_eq!(asked, DECODES_ASKED, "the cases put to {DECODER}");
}
