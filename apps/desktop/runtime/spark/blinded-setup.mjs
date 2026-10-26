// Checkout-only setup for the blinded regtest worker. The launcher and the
// headless driver share it so both run with the same environment and prover.
import { accessSync, constants, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { acceleratedProver, RUNTIME_W8 } from './prover.mjs';

export const NETWORK = /^[a-z][a-z0-9_-]{0,31}$/;
const SUITES = {
  ZARK_SPARK_REAL_SUITE: 'work/spark-suites/ownership/manifest.json',
  ZARK_SPARK_RECEIVE_SUITE: 'work/spark-suites/receive/manifest.json',
  ZARK_SPARK_NATIVE_SUITE: 'work/spark-suites/ordinary-native/manifest.json',
  ZARK_SPARK_AUTH_SUITE: 'work/spark-suites/auth/manifest.json',
};
const FLAGS = { ZARK_SPARK_ECDSA_2P: '1', ZARK_SPARK_ADDITIVE_RECEIVE: '1', ZARK_TIMINGS: '1', ZARK_SPARK_PROVE_THREADS: '8' };
// One-shot test controls and prover overrides from a developer shell must
// never steer a desktop session; the prover runtime is set only after its check.
export const STRIPPED = ['ZARK_SPARK_INITIALISE_WITNESS', 'ZARK_SPARK_PROVING_RUNTIME', 'BB_MSM_NEW'];

export const WORKER_BUILD = ['test', '--locked', '--offline', '--manifest-path', 'integrations/spark/cosigner/Cargo.toml',
  '--features', 'ecdsa-2p', '--lib', '--no-run', '--message-format=json'];
export function workerBuildEnvironment(root) {
  if (!existsSync(path.join(root, 'work/cbmpc/BUILD-INFO'))) throw new Error('cb-mpc is not built (work/cbmpc/BUILD-INFO missing); run python3 scripts/setup-demo.py first.');
  // Shares the cosigner's development target; differing profile settings would rebuild it from scratch.
  return { CARGO_HOME: path.join(root, 'work/cargo'), CARGO_TARGET_DIR: path.join(root, 'work/implementation-target'),
    CARGO_BUILD_JOBS: '1', CARGO_INCREMENTAL: '0' };
}

const executable = file => { try { accessSync(file, constants.X_OK); return statSync(file).isFile(); } catch { return false; } };

export function resolveDocker(env, isExecutable = executable) {
  if (env.ZARK_SPARK_DOCKER) {
    if (path.isAbsolute(env.ZARK_SPARK_DOCKER) && isExecutable(env.ZARK_SPARK_DOCKER)) return env.ZARK_SPARK_DOCKER;
    throw new Error('ZARK_SPARK_DOCKER must be an absolute path to the Docker CLI.');
  }
  if (isExecutable('/usr/local/bin/docker')) return '/usr/local/bin/docker';
  for (const directory of (env.PATH ?? '').split(path.delimiter).filter(Boolean)) {
    const candidate = path.resolve(directory, 'docker');
    if (isExecutable(candidate)) return candidate;
  }
  throw new Error('Docker CLI not found; start Docker Desktop or set ZARK_SPARK_DOCKER.');
}

/** Environment for `zark-desktop`/`main.mjs`, without the profile. */
export async function blindedEnvironment({ root, env = process.env, binary, node = process.execPath, prover = acceleratedProver, isExecutable }) {
  const network = env.ZARK_SPARK_NETWORK ?? 'demo';
  if (!NETWORK.test(network)) throw new Error('ZARK_SPARK_NETWORK must be a lowercase name like demo-1021.');
  const suites = {};
  for (const [key, file] of Object.entries(SUITES)) {
    suites[key] = path.join(root, file);
    if (!existsSync(suites[key])) throw new Error(`${key} manifest missing at ${suites[key]}; run python3 scripts/setup-demo.py.`);
  }
  const docker = resolveDocker(env, isExecutable);
  const choice = await prover(path.join(root, RUNTIME_W8));
  const inherited = { ...env };
  for (const key of STRIPPED) delete inherited[key];
  return { prover: choice, env: { ...inherited, ZARK_PREVIEW: '0', ZARK_NODE: node,
    ZARK_DESKTOP_RUNTIME: path.join(root, 'apps/desktop/runtime/spark/main.mjs'), ZARK_SPARK_NETWORK: network, ZARK_SPARK_DOCKER: docker,
    ...suites, ...FLAGS, ...(binary ? { ZARK_SPARK_DESKTOP_BINARY: binary } : {}),
    ...(choice.runtime ? { ZARK_SPARK_PROVING_RUNTIME: choice.runtime } : {}) } };
}
