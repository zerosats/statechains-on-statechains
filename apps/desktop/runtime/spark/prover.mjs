// Accelerated proving is used only for the qualified runtime-w8 profile whose
// executor and prover binaries match pinned hashes. Any doubt falls back to
// stock bb. Proofs are verified with stock bb against pinned VKs either way.
import { createHash } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { access, readFile } from 'node:fs/promises';
import path from 'node:path';

export const RUNTIME_W8 = 'work/fast-runtime-qualification-20261020/runtime-w8/runtime.json';
export const PINNED = {
  executor: 'b88082ca57624adc4d5380d55b6c7ae25b33bd18b4df99d3edd8d20b73a2c5da',
  prover: '5225d6af8a1ae35710f88a31e5ef76fe2554b4e5a07e9b50236af42dea54aaf9',
};
// The Rust loader denies unknown fields; these are the ones it knows.
const KEYS = ['executor', 'prover', 'witness_threads', 'prove_threads', 'fast_msm'];

export function sha256File(file) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    createReadStream(file).on('error', reject).on('data', chunk => hash.update(chunk)).on('end', () => resolve(hash.digest('hex')));
  });
}

const hex = bytes => Array.isArray(bytes) && bytes.length === 32 && bytes.every(b => Number.isInteger(b) && b >= 0 && b <= 255)
  ? Buffer.from(bytes).toString('hex') : null;
const short = digest => `${digest.slice(0, 8)}…`;

async function unavailable(runtimePath, expected) {
  let runtime;
  try { runtime = JSON.parse(await readFile(runtimePath, 'utf8')); }
  catch (error) { return error.code === 'ENOENT' ? 'runtime-w8 not found' : 'runtime-w8 runtime.json unreadable'; }
  if (!runtime || typeof runtime !== 'object' || Array.isArray(runtime) || Object.keys(runtime).some(key => !KEYS.includes(key))) return 'unexpected runtime.json shape';
  if (runtime.witness_threads !== 8 || runtime.prove_threads !== 8 || runtime.fast_msm !== true) return 'runtime.json is not the 8-thread fast-MSM profile';
  for (const role of ['executor', 'prover']) {
    const pin = runtime[role];
    if (!pin || typeof pin.path !== 'string' || !path.isAbsolute(pin.path)) return `${role} path missing`;
    if (hex(pin.sha256) !== expected[role]) return `${role} pin in runtime.json is not ${short(expected[role])}`;
    try { await access(pin.path, constants.X_OK); } catch { return `${role} binary missing or not executable`; }
    let actual;
    try { actual = await sha256File(pin.path); } catch { return `${role} binary unreadable`; }
    if (actual !== expected[role]) return `${role} binary is ${short(actual)}, expected ${short(expected[role])}`;
  }
  return null;
}

/** `{ runtime, message }`; `runtime` is the absolute runtime.json path or null for stock bb. */
export async function acceleratedProver(runtimePath, { expected = PINNED } = {}) {
  const reason = await unavailable(runtimePath, expected);
  if (reason) return { runtime: null, message: `Spark desktop: accelerated prover unavailable (${reason}); using stock bb (slower)` };
  return { runtime: runtimePath, message: `Spark desktop: accelerated prover runtime-w8 (fast executor ${short(expected.executor)}, bb-cap15 ${short(expected.prover)}, BB_MSM_NEW=1, 8 threads); proofs verify with stock bb against pinned VKs` };
}
