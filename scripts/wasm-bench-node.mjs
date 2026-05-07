// Run the mmiyc-bench WASI artefact under Node.js's V8 WebAssembly engine.
//
// Companion to `wasmtime run …`: produces a second data point for the
// WASM-prover-feasibility table in section 6.2 of the paper.  The two
// engines (wasmtime AOT vs V8 baseline+TurboFan) give us a defensible
// estimate of the variability across deployment targets.
//
// Usage:
//   node scripts/wasm-bench-node.mjs            # default ladder
//   node scripts/wasm-bench-node.mjs --air all --iters 10 …
//
// Forwards positional args to the wasm program.

import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';
import { argv, exit, hrtime } from 'node:process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const wasmPath = path.resolve(
  __dirname,
  '..',
  'target',
  'wasm32-wasip1',
  'release',
  'mmiyc-bench.wasm',
);

// All forwarded args go to the wasm guest program.  Default to the
// same ladder we use under wasmtime so the two outputs line up.
const guestArgs = argv.slice(2).length
  ? argv.slice(2)
  : ['bench', '--air', 'all', '--iters', '10'];

const wasi = new WASI({
  version: 'preview1',
  args: ['mmiyc-bench', ...guestArgs],
  env: {},
  preopens: { '/': process.cwd() },
});

const t0 = hrtime.bigint();
const wasmBytes = await readFile(wasmPath);
const wasmModule = await WebAssembly.compile(wasmBytes);
const instance   = await WebAssembly.instantiate(wasmModule, wasi.getImportObject());
const tCompile = Number(hrtime.bigint() - t0) / 1e6;

console.error(`# node:wasi v8 — module compile + instantiate: ${tCompile.toFixed(1)} ms`);
const exitCode = wasi.start(instance);
exit(exitCode ?? 0);
