// Copyright (c) 2026 Tymofii Kosovskyi
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// V8's own reading of a WebAssembly module, through node's inspector: the
// module is compiled with `new WebAssembly.Module`, V8 reports it to the
// debugger as a script, and `Debugger.disassembleWasmModule` with
// `Debugger.nextWasmDisassemblyChunk` gives every line of V8's disassembly.
// Each line is printed as `OFFSET: text`, OFFSET being the byte offset in the
// module that V8 gives for the line, in hexadecimal, six digits at least.
//
//   node v8dis.mjs MODULE.wasm             the disassembly, on stdout
//   node v8dis.mjs --validate MODULE.wasm  only compile: V8 as a validator
//
// Exit status 0: V8 compiled the module (and, without --validate, the whole
// disassembly is on stdout). 1: V8 refused the module; its message is on
// stderr and nothing is on stdout. 2: anything else went wrong (a protocol
// error, no script reported in time, a script whose bytes are not the
// module's, chunks that do not add up); the reason is on stderr. Nothing but
// the disassembly is ever written to stdout.

import fs from 'node:fs';
import inspector from 'node:inspector';

// How long V8 may take to report the compiled module as a script, and how
// often to look. The report normally arrives during compilation itself.
const SCRIPT_WAIT_MS = 5000;
const POLL_MS = 10;

class Failure extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function usage() {
  return new Failure(2, 'usage: node v8dis.mjs [--validate] MODULE.wasm');
}

async function main(argv) {
  const validateOnly = argv[0] === '--validate';
  const files = validateOnly ? argv.slice(1) : argv;
  if (files.length !== 1) throw usage();
  const bytes = fs.readFileSync(files[0]);

  if (validateOnly) {
    compile(bytes);
    return '';
  }

  const session = new inspector.Session();
  session.connect();
  try {
    const post = (method, params) =>
      new Promise((resolve, reject) =>
        session.post(method, params, (error, result) =>
          error ? reject(new Failure(2, `${method}: ${error.message}`)) : resolve(result)));

    // Every WebAssembly script V8 reports, in order. Enabling the debugger
    // reports the ones that already exist; only a script reported after the
    // module is compiled can be this module.
    const reported = [];
    session.on('Debugger.scriptParsed', (message) => {
      if (message.params.scriptLanguage === 'WebAssembly') reported.push(message.params.scriptId);
    });
    await post('Debugger.enable', {});
    const before = reported.length;
    compile(bytes);
    const deadline = Date.now() + SCRIPT_WAIT_MS;
    while (reported.length === before && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    }
    const ours = reported.slice(before);
    if (ours.length !== 1) {
      throw new Failure(2, `${ours.length} WebAssembly scripts reported within ${SCRIPT_WAIT_MS} ms of compiling the module, not 1`);
    }
    const scriptId = ours[0];

    // The script must hold exactly the module's bytes, or the disassembly is
    // of something else.
    const source = await post('Debugger.getScriptSource', { scriptId });
    if (typeof source.bytecode !== 'string' || !Buffer.from(source.bytecode, 'base64').equals(bytes)) {
      throw new Failure(2, 'the reported script does not hold the module\'s bytes');
    }

    const out = [];
    const take = (chunk) => {
      if (!chunk || !Array.isArray(chunk.lines) || !Array.isArray(chunk.bytecodeOffsets)
          || chunk.lines.length !== chunk.bytecodeOffsets.length) {
        throw new Failure(2, 'a disassembly chunk whose lines and offsets do not pair up');
      }
      for (let i = 0; i < chunk.lines.length; i++) {
        out.push(`${chunk.bytecodeOffsets[i].toString(16).padStart(6, '0')}: ${chunk.lines[i]}`);
      }
      return chunk.lines.length;
    };
    const first = await post('Debugger.disassembleWasmModule', { scriptId });
    take(first.chunk);
    // Without a stream the first chunk is the whole module; with one, the
    // stream ends with an empty chunk.
    if (first.streamId !== undefined) {
      for (;;) {
        const next = await post('Debugger.nextWasmDisassemblyChunk', { streamId: first.streamId });
        if (take(next.chunk) === 0) break;
      }
    }
    if (out.length !== first.totalNumberOfLines) {
      throw new Failure(2, `${out.length} lines received, ${first.totalNumberOfLines} announced`);
    }
    await post('Debugger.disable', {});
    return out.join('\n') + '\n';
  } finally {
    session.disconnect();
  }
}

function compile(bytes) {
  try {
    new WebAssembly.Module(bytes);
  } catch (error) {
    throw new Failure(1, `V8 refuses the module: ${error.message}`);
  }
}

try {
  const text = await main(process.argv.slice(2));
  if (text) process.stdout.write(text);
} catch (error) {
  process.stderr.write(`v8dis.mjs: ${error.message}\n`);
  process.exitCode = error instanceof Failure ? error.status : 2;
}
