// Checkout-only prototype launcher. Builds the explicit test worker, not a
// signer with a production proof bypass. Never starts/resets native services.
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { blindedEnvironment, WORKER_BUILD, workerBuildEnvironment } from './blinded-setup.mjs';
import { acceleratedProver, RUNTIME_W8 } from './prover.mjs';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const [mode, name, ...extra] = process.argv.slice(2);
const named = mode === '--blinded' || mode === '--preview';
const profile = (named ? name : undefined) ?? 'wallet';
if (!['--blinded', '--blinded-build', '--preview'].includes(mode) || !/^[a-z][a-z0-9_-]{0,31}$/.test(profile) ||
    extra.length || (!named && name !== undefined)) {
  throw new Error('Usage: ./run-wallet.sh --blinded [wallet-name] | --preview [wallet-name] | --blinded-build');
}
const cargo = process.env.ZARK_SPARK_CARGO ?? 'cargo';
const env = { ...process.env, CARGO_BUILD_JOBS: '1' };

async function command(program, argv, { capture = false, extra = {}, base = env } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(program, argv, { cwd: root, env: { ...base, ...extra }, stdio: ['inherit', capture ? 'pipe' : 'inherit', 'inherit'] });
    let output = '';
    child.stdout?.on('data', bytes => { output += bytes; });
    child.once('error', reject);
    child.once('close', code => code === 0 ? resolve(output) : reject(new Error(`${program} exited with ${code}`)));
  });
}

function testExecutable(built) {
  let executable;
  for (const line of built.trim().split('\n')) {
    const item = JSON.parse(line);
    if (item.reason === 'compiler-artifact' && item.profile?.test && item.target?.name === 'zark_spark_cosigner' && item.executable) executable = item.executable;
  }
  if (!executable) throw new Error('Spark desktop test executable was not produced.');
  return executable;
}

const buildDesktop = () => command(cargo, ['build', '--locked', '--manifest-path', 'apps/desktop-tauri/Cargo.toml', '--target-dir', 'apps/desktop-tauri/target']);
const openDesktop = (extra, base = env) => command(path.join(root, 'apps/desktop-tauri/target/debug/zark-desktop'), [], { extra, base });

async function runBlinded() {
  const buildEnvironment = workerBuildEnvironment(root);
  // Check the session prerequisites before a long build.
  const session = mode === '--blinded' ? await blindedEnvironment({ root, env }) : null;
  console.log((session?.prover ?? await acceleratedProver(path.join(root, RUNTIME_W8))).message);
  console.log('Building the blinded Spark regtest desktop worker. Native services and retained wallets are left running as configured.');
  const executable = testExecutable(await command(cargo, WORKER_BUILD, { capture: true, extra: buildEnvironment }));
  if (!session) { console.log(`ZARK_SPARK_DESKTOP_BINARY=${executable}`); return; }
  await buildDesktop();
  await openDesktop({ ZARK_PROFILE: profile, ZARK_SPARK_DESKTOP_BINARY: executable }, session.env);
}

/** Synthetic display data only; never builds or starts a worker. */
async function runPreview() {
  await buildDesktop();
  await openDesktop({ ZARK_PROFILE: profile, ZARK_PREVIEW: '1', ZARK_NODE: process.execPath,
    ZARK_DESKTOP_RUNTIME: path.join(root, 'apps/desktop/runtime/spark/main.mjs') });
}

try {
  const version = await command(cargo, ['--version'], { capture: true });
  if (!version.startsWith('cargo 1.95.0 ')) throw new Error('Spark desktop requires the pinned Rust 1.95.0 toolchain.');
  await (mode === '--preview' ? runPreview() : runBlinded());
} catch (error) {
  console.error(`Spark desktop: ${error.message}`);
  process.exitCode = 1;
}
