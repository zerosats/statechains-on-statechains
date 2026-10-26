import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { acceleratedProver, PINNED } from './spark/prover.mjs';
import { blindedEnvironment, resolveDocker, STRIPPED, WORKER_BUILD, workerBuildEnvironment } from './spark/blinded-setup.mjs';

const digest = text => createHash('sha256').update(text).digest('hex');
const bytes = hex => [...Buffer.from(hex, 'hex')];

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'zark-prover-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const executor = path.join(root, 'noir-execute-fast'), prover = path.join(root, 'bb-cap15');
  await writeFile(executor, 'fake executor', { mode: 0o755 });
  await writeFile(prover, 'fake prover', { mode: 0o755 });
  const expected = { executor: digest('fake executor'), prover: digest('fake prover') };
  const runtime = path.join(root, 'runtime.json');
  const write = value => writeFile(runtime, typeof value === 'string' ? value : JSON.stringify(value));
  const good = { executor: { path: executor, sha256: bytes(expected.executor) }, prover: { path: prover, sha256: bytes(expected.prover) },
    witness_threads: 8, prove_threads: 8, fast_msm: true };
  return { root, executor, prover, expected, runtime, write, good };
}

test('accelerated prover pins the qualified runtime-w8 binaries', () => {
  assert.deepEqual(PINNED, { executor: 'b88082ca57624adc4d5380d55b6c7ae25b33bd18b4df99d3edd8d20b73a2c5da',
    prover: '5225d6af8a1ae35710f88a31e5ef76fe2554b4e5a07e9b50236af42dea54aaf9' });
});

test('accelerated prover is selected only when the runtime and both binaries match their pins', async t => {
  const { runtime, write, good, expected } = await fixture(t);
  await write(good);
  const chosen = await acceleratedProver(runtime, { expected });
  assert.equal(chosen.runtime, runtime);
  assert.equal(chosen.message, `Spark desktop: accelerated prover runtime-w8 (fast executor ${expected.executor.slice(0, 8)}…, bb-cap15 ${expected.prover.slice(0, 8)}…, BB_MSM_NEW=1, 8 threads); proofs verify with stock bb against pinned VKs`);
  // The real pins never match the fake binaries.
  assert.equal((await acceleratedProver(runtime)).runtime, null);
});

test('accelerated prover falls back to stock bb with one reason on any doubt', async t => {
  const { root, executor, prover, runtime, write, good, expected } = await fixture(t);
  const other = digest('other');
  const cases = [
    [() => rm(runtime, { force: true }), /runtime-w8 not found/],
    [() => write('{not json'), /unreadable/],
    [() => write([]), /unexpected runtime.json shape/],
    [() => write({ ...good, env: { BB_MSM_NEW: '1' } }), /unexpected runtime.json shape/],
    [() => write({ ...good, witness_threads: 4 }), /8-thread fast-MSM/],
    [() => write({ ...good, prove_threads: 2 }), /8-thread fast-MSM/],
    [() => write({ ...good, fast_msm: false }), /8-thread fast-MSM/],
    [() => write({ ...good, helper: good.executor }), /unexpected runtime.json shape/],
    [() => write({ ...good, executor: { ...good.executor, path: 'noir-execute-fast' } }), /executor path missing/],
    [() => write({ ...good, prover: { ...good.prover, sha256: bytes(other) } }), /prover pin in runtime.json/],
    [() => write({ ...good, executor: { ...good.executor, sha256: [1, 2, 3] } }), /executor pin in runtime.json/],
    [async () => { await write(good); await writeFile(prover, 'tampered prover'); }, /prover binary is [a-f0-9]{8}…, expected/],
    [async () => { await writeFile(prover, 'fake prover'); await chmod(executor, 0o644); }, /executor binary missing or not executable/],
    [async () => { await rm(executor); }, /executor binary missing or not executable/],
    [async () => { await writeFile(executor, 'fake executor', { mode: 0o755 }); await write({ ...good, prover: { ...good.prover, path: path.join(root, 'absent') } }); },
      /prover binary missing/],
  ];
  for (const [arrange, reason] of cases) {
    await arrange();
    const chosen = await acceleratedProver(runtime, { expected });
    assert.equal(chosen.runtime, null, String(reason));
    assert.match(chosen.message, /^Spark desktop: accelerated prover unavailable \(.+\); using stock bb \(slower\)$/);
    assert.match(chosen.message, reason);
  }
});

async function suites(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'zark-blinded-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const name of ['ownership', 'receive', 'ordinary-native', 'auth']) {
    await mkdir(path.join(root, 'work/spark-suites', name), { recursive: true });
    await writeFile(path.join(root, 'work/spark-suites', name, 'manifest.json'), '{}');
  }
  return root;
}

test('blinded session environment sets the documented backend inputs and strips one-shot controls', async t => {
  const root = await suites(t);
  const inherited = Object.fromEntries(STRIPPED.map(key => [key, 'inherited']));
  const docker = file => file === '/usr/local/bin/docker';
  const accelerated = async file => ({ runtime: file, message: 'fast' });
  const { env, prover } = await blindedEnvironment({ root, env: { ...inherited, HOME: '/home/test' }, binary: '/abs/test-exe', node: '/abs/node',
    prover: accelerated, isExecutable: docker });
  assert.equal(prover.message, 'fast');
  assert.deepEqual(env, {
    HOME: '/home/test', ZARK_PREVIEW: '0', ZARK_NODE: '/abs/node',
    ZARK_DESKTOP_RUNTIME: path.join(root, 'apps/desktop/runtime/spark/main.mjs'), ZARK_SPARK_NETWORK: 'demo', ZARK_SPARK_DOCKER: '/usr/local/bin/docker',
    ZARK_SPARK_REAL_SUITE: path.join(root, 'work/spark-suites/ownership/manifest.json'),
    ZARK_SPARK_RECEIVE_SUITE: path.join(root, 'work/spark-suites/receive/manifest.json'),
    ZARK_SPARK_NATIVE_SUITE: path.join(root, 'work/spark-suites/ordinary-native/manifest.json'),
    ZARK_SPARK_AUTH_SUITE: path.join(root, 'work/spark-suites/auth/manifest.json'),
    ZARK_SPARK_ECDSA_2P: '1', ZARK_SPARK_ADDITIVE_RECEIVE: '1', ZARK_TIMINGS: '1', ZARK_SPARK_PROVE_THREADS: '8',
    ZARK_SPARK_DESKTOP_BINARY: '/abs/test-exe',
    ZARK_SPARK_PROVING_RUNTIME: path.join(root, 'work/fast-runtime-qualification-20261020/runtime-w8/runtime.json'),
  });
  const stock = await blindedEnvironment({ root, env: { ...inherited, ZARK_SPARK_NETWORK: 'demo-1021' }, prover: async () => ({ runtime: null, message: 'stock' }), isExecutable: docker });
  assert.equal(stock.env.ZARK_SPARK_NETWORK, 'demo-1021');
  for (const key of STRIPPED) assert.equal(Object.hasOwn(stock.env, key), false, key);
});

test('blinded session refuses bad network names and missing suites before building', async t => {
  const root = await suites(t);
  const options = { root, prover: async () => ({ runtime: null, message: '' }), isExecutable: () => true };
  for (const network of ['', 'Demo', '1demo', 'demo/../x', 'a'.repeat(33)]) {
    await assert.rejects(blindedEnvironment({ ...options, env: { ZARK_SPARK_NETWORK: network } }), /ZARK_SPARK_NETWORK/);
  }
  await rm(path.join(root, 'work/spark-suites/auth/manifest.json'));
  await assert.rejects(blindedEnvironment({ ...options, env: {} }), /ZARK_SPARK_AUTH_SUITE manifest missing/);
});

test('Docker CLI resolves to an absolute executable', () => {
  assert.equal(resolveDocker({ ZARK_SPARK_DOCKER: '/opt/docker' }, file => file === '/opt/docker'), '/opt/docker');
  assert.throws(() => resolveDocker({ ZARK_SPARK_DOCKER: 'docker' }, () => true), /absolute path/);
  assert.equal(resolveDocker({ PATH: ['relative/bin', '/opt/bin'].join(path.delimiter) }, file => file === '/opt/bin/docker'), '/opt/bin/docker');
  assert.equal(resolveDocker({ PATH: 'relative/bin' }, file => file === path.resolve('relative/bin/docker')), path.resolve('relative/bin/docker'));
  assert.throws(() => resolveDocker({ PATH: '/opt/bin' }, () => false), /Docker CLI not found/);
});

test('blinded worker build requires cb-mpc and shares the cosigner development target', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'zark-cbmpc-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  assert.throws(() => workerBuildEnvironment(root), /run python3 scripts\/setup-demo\.py/);
  await mkdir(path.join(root, 'work/cbmpc'), { recursive: true });
  await writeFile(path.join(root, 'work/cbmpc/BUILD-INFO'), '');
  assert.deepEqual(workerBuildEnvironment(root), { CARGO_HOME: path.join(root, 'work/cargo'),
    CARGO_TARGET_DIR: path.join(root, 'work/implementation-target'), CARGO_BUILD_JOBS: '1', CARGO_INCREMENTAL: '0' });
  assert.deepEqual(WORKER_BUILD, ['test', '--locked', '--offline', '--manifest-path', 'integrations/spark/cosigner/Cargo.toml',
    '--features', 'ecdsa-2p', '--lib', '--no-run', '--message-format=json']);
});
