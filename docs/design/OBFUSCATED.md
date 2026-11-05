# Obfuscated code: what can be believed

Status: accepted 2026-11-05. Two transformations of the list below are measured, junk bytes and lying tables on ELF (`docs/VERIFICATION.md`); on the others how the engine behaves is unknown.

## 1. Why it changes the argument

`why` and the rule measurements (`WHY.md`, `docs/VERIFICATION.md`) report that a start declared by a
table was never wrong on the corpus. That holds for honest compilers: the table and the truth have
one author. A table is a claim, and a transformed image can lie in it. So:

- an answer never states a table's claim as truth: `why` says who claims it;
- claims are cross-checked against the code where the code can answer: a start that does not decode,
  an unwind range ending mid-instruction, a call into the middle of a declared function, overlapping
  decodes. These become kinds of `contradictions`;
- the aim on such code is "not sure, and here is why" instead of a wrong answer in silence.

## 2. The measurement

The question: which answers are confidently wrong, and does anything in the answer warn of it?

Transformations are applied in LLVM IR or assembly, where symbols are still labels, so the build's own
debug information stays correct, read by an independent tool, and the transformed program must still
give the same output. Lying tables are tampered with after the link, so the truth is the file before
tampering. Real instruction boundaries come from the assembler's listing, because a disassembler
desynchronizes on junk bytes too. Each is measured alone before any combination, at more than one
intensity, so a wrong answer can be traced to one cause:

- junk bytes after unconditional transfers;
- opaque predicates with a never-taken branch into junk;
- flattened control flow;
- strings encrypted until run time;
- calls through computed tables;
- overlapping instructions and jumps into the middle of one;
- lying tables: a false unwind entry or range, a false function symbol or size, unwind tables removed,
  exports renamed; for WebAssembly a forged name section;
- a packer: what a static reader can and cannot see, stated as such.

The number that matters is **silent or flagged**: of the wrong answers, how many carried any warning (a
source that is only a heuristic, a place listed by `contradictions`, a refusal), and how many were
`ok: true` with nothing. A crash, a hang or unbounded memory is a defect of its own.

`ir deobfuscate` already detects junk instructions and opaque predicates in a function, and has never
been measured on such code: it is scored here too, including how often it flags honest code.

WebAssembly differs: a validator enforces function bounds, so those survive; its name section does not.

Whichever claims of `WHY.md` do not hold here are corrected there with the numbers, the verdict "a
fact's category predicts its error" first of all.
