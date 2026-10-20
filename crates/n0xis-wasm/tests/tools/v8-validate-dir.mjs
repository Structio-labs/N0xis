// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// V8 as a validator of many modules in one process: every `*.wasm` file of a
// directory is compiled with `new WebAssembly.Module`, and one line per file
// is written to stdout, in the order of the sorted file names:
//
//   NAME<TAB>accepts
//   NAME<TAB>refuses<TAB>V8's message
//
//   node v8-validate-dir.mjs DIRECTORY
//
// `tests/sweep.rs` uses it, where one node process per module would take
// minutes. Only a `WebAssembly.CompileError` is a refusal: any other exception
// is not a verdict on the bytes, and stops the script.
//
// Exit status 0: every file was judged, and its line written. 2: anything else
// (no directory, no `.wasm` file in it, a file that cannot be read, an
// exception other than a compile error); the reason is on stderr, and what was
// written to stdout before it is not to be read as a complete answer.

import fs from 'node:fs';
import path from 'node:path';

function fail(message) {
  process.stderr.write(`v8-validate-dir.mjs: ${message}\n`);
  process.exit(2);
}

const argv = process.argv.slice(2);
if (argv.length !== 1) fail('usage: node v8-validate-dir.mjs DIRECTORY');
const dir = argv[0];

let names;
try {
  names = fs.readdirSync(dir).filter((n) => n.endsWith('.wasm')).sort();
} catch (error) {
  fail(`${dir}: ${error.message}`);
}
if (names.length === 0) fail(`${dir}: no .wasm file`);

const lines = [];
for (const name of names) {
  let bytes;
  try {
    bytes = fs.readFileSync(path.join(dir, name));
  } catch (error) {
    fail(`${name}: ${error.message}`);
  }
  try {
    new WebAssembly.Module(bytes);
    lines.push(`${name}\taccepts`);
  } catch (error) {
    if (!(error instanceof WebAssembly.CompileError)) fail(`${name}: not a compile error: ${error}`);
    // A message is one line, so that one file is one line.
    lines.push(`${name}\trefuses\t${String(error.message).replace(/\s+/g, ' ')}`);
  }
}
process.stdout.write(lines.join('\n') + '\n');
