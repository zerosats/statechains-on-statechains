// Explicit live check of the blinded desktop backend: three app runtimes on a
// NEW network, Public -> Incognito -> private handovers -> Public, then a
// restart. Existing networks, native services and pending operations are retained.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createWriteStream, existsSync, mkdirSync } from 'node:fs';
import { createInterface } from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { blindedEnvironment, NETWORK } from '../apps/desktop/runtime/spark/blinded-setup.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const network = process.argv[2], binary = process.env.ZARK_SPARK_DESKTOP_BINARY;
if (process.argv.length !== 3 || !NETWORK.test(network ?? '') || !path.isAbsolute(binary ?? '')) {
  throw new Error('Usage: ZARK_SPARK_DESKTOP_BINARY=/absolute/test-executable node scripts/check-spark-blinded-desktop.mjs new-network-name');
}
assert.equal(existsSync(path.join(root, 'work/zark-spark/blinded-networks', network)), false, 'Use a new network; never replace retained state');

const PROFILES = ['alice', 'bob', 'carol'];
const DEPOSITS = [10000, 5000];
const TWO_COINS = 15000, ONE_COIN = 5000;
const FORWARDED = /^(ZARK_STAGE_TIMING|ZARK_EXIT_TIMING|Real Spark ownership|Spark desktop)/;
// Phases of the slower paths the blinded backend replaces; seeing one is a regression.
const FORBIDDEN = ['native_tweak_gc_mpc', 'leaf_signature_ecdsa', 'exit_proof'];

const { env, prover } = await blindedEnvironment({ root, env: { ...process.env, ZARK_SPARK_NETWORK: network }, binary });
mkdirSync(path.join(root, 'work/logs'), { recursive: true });
const log = createWriteStream(path.join(root, `work/logs/blinded-driver-${network}.log`), { flags: 'a', mode: 0o600 });
const note = line => { console.log(line); log.write(`${line}\n`); };
const phases = new Map(), stages = new Set(), steps = [];
const started = performance.now();

class Client {
  constructor(profile) {
    this.profile = profile; this.pending = new Map(); this.sequence = 0;
    this.child = spawn(process.execPath, [env.ZARK_DESKTOP_RUNTIME], {
      env: { ...env, ZARK_PROFILE: profile, ZARK_SPARK_FORWARD_TIMINGS: '1' }, stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.closed = new Promise(resolve => this.child.once('close', code => {
      for (const request of this.pending.values()) request.reject(new Error(`${profile} app stopped (${code}); retain ${network}`));
      this.pending.clear();
      resolve();
    }));
    createInterface({ input: this.child.stdout }).on('line', line => this.event(JSON.parse(line)));
    createInterface({ input: this.child.stderr }).on('line', line => this.diagnostic(line));
  }
  event(event) {
    if (event.snapshot?.blinded) this.snapshot = event.snapshot.blinded;
    if (event.stage) stages.add(`${event.stage.operation}.${event.stage.step}`);
    if (event.preview) this.preview = event.preview;
    const request = this.pending.get(event.id);
    if (request) {
      this.pending.delete(event.id);
      if (event.error) request.reject(new Error(`${this.profile}: ${event.error} (${event.errorCode ?? 'no code'}); retain ${network}`));
      else request.resolve();
    } else if (event.error) console.error(`[${this.profile}] ${event.error}`);
  }
  diagnostic(line) {
    if (!FORWARDED.test(line)) return;
    note(`[${this.profile}] ${line}`);
    const timing = /^ZARK_(?:STAGE|EXIT)_TIMING (\{.*\})$/.exec(line);
    if (!timing) return;
    try {
      const { phase, milliseconds } = JSON.parse(timing[1]);
      const seen = phases.get(phase) ?? { count: 0, milliseconds: 0 };
      seen.count += 1; seen.milliseconds += milliseconds;
      phases.set(phase, seen);
    } catch { /* The worker filter forwards fixed-format lines only. */ }
  }
  action(action, args = {}) {
    const id = `check-${++this.sequence}`;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.child.stdin.write(`${JSON.stringify({ id, action, args })}\n`);
    });
  }
  get public() { return this.snapshot.public; }
  get incognito() { return this.snapshot.incognito; }
  coin() { return this.incognito.coins.find(coin => coin.state === 'available'); }
  balances() {
    return { public: { address: this.public.address, totalSat: this.public.totalSat },
      incognito: { address: this.incognito.address, totalSat: this.incognito.totalSat } };
  }
  async close() { this.child.stdin.end(); await this.closed; }
}

async function step(name, run) {
  const begun = performance.now();
  await run();
  const seconds = (performance.now() - begun) / 1000;
  steps.push({ step: name, seconds: Number(seconds.toFixed(2)) });
  note(`STEP ${name}: ${seconds.toFixed(2)} s`);
}

// Refresh polls also run the recipient's automatic claim.
async function until(client, ready, label, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (!(client.snapshot && ready(client.snapshot))) {
    if (Date.now() > deadline) throw new Error(`${label} not observed within ${timeoutMs / 1000} s; retain ${network}`);
    await new Promise(resolve => setTimeout(resolve, 2000));
    await client.action('refresh');
  }
}

const open = () => PROFILES.map(profile => new Client(profile));
const named = clients => Object.fromEntries(clients.map(client => [client.profile, client]));
const balances = clients => Object.fromEntries(clients.map(client => [client.profile, client.balances()]));
const available = snapshot => snapshot.incognito.coins.some(coin => coin.state === 'available');

note(prover.message);
note(`Blinded desktop check on new network ${network}`);
let clients = open(), final, failure;
try {
  const { alice, bob, carol } = named(clients);
  await step('refresh all', () => Promise.all(clients.map(client => client.action('refresh'))));
  for (const side of ['public', 'incognito']) assert.equal(new Set(clients.map(client => client[side].address)).size, 3, `distinct ${side} addresses`);

  for (const amountSat of DEPOSITS) await step(`alice publicDeposit ${amountSat}`, () => alice.action('publicDeposit', { amountSat }));
  assert.deepEqual(alice.public.leaves.map(leaf => leaf.amountSat).sort((a, b) => b - a), DEPOSITS);
  assert.equal(alice.public.totalSat, TWO_COINS);
  await until(alice, snapshot => snapshot.public.leaves.filter(leaf => leaf.available).length === 2, 'alice available Public leaves', 60_000);

  for (const leaf of alice.public.leaves) await step(`alice goPrivate ${leaf.amountSat}`, () => alice.action('goPrivate', { leaf: leaf.id }));
  assert.equal(alice.incognito.totalSat, TWO_COINS);
  assert.equal(alice.public.totalSat, 0);

  const both = alice.incognito.coins.map(coin => coin.id);
  await step('alice preview', () => alice.action('preview', { side: 'incognito', address: bob.incognito.address, coins: both }));
  assert.equal(alice.preview.amountSat, TWO_COINS);
  assert.deepEqual(alice.preview.inputs, both);
  await step('alice privateSend two coins to bob', () => alice.action('privateSend', { address: bob.incognito.address, coins: both }));
  assert.equal(alice.incognito.totalSat, 0);
  await step('bob automatic claims', () => until(bob, snapshot => snapshot.incognito.totalSat === TWO_COINS, 'bob incoming coins', 360_000));

  const five = bob.incognito.coins.find(coin => coin.state === 'available' && coin.amountSat === ONE_COIN).id;
  await step('bob privateSend one coin to carol', () => bob.action('privateSend', { address: carol.incognito.address, coins: [five] }));
  assert.equal(bob.incognito.totalSat, TWO_COINS - ONE_COIN);
  await step('carol automatic claim', () => until(carol, available, 'carol incoming coin', 180_000));

  await step('carol goPublic', () => carol.action('goPublic', { coin: carol.coin().id }));
  assert.equal(carol.public.totalSat, ONE_COIN);
  assert.equal(carol.incognito.totalSat, 0);
  await step('carol publicDeposit whole set', () => carol.action('publicDeposit', { amountSat: 19000 }));
  assert.equal(carol.public.totalSat, ONE_COIN + 19000);
  assert.equal(carol.public.leaves.length, 5);

  const before = balances(clients);
  await step('close all', () => Promise.all(clients.map(client => client.close())));
  clients = open();
  await step('reopen and refresh all', () => Promise.all(clients.map(client => client.action('refresh'))));
  assert.deepEqual(balances(clients), before);
  for (const client of clients) assert.notEqual(client.snapshot.status, 'blocked', `${client.profile} is blocked`);
  final = before;
} catch (error) {
  failure = error;
} finally {
  // Closing stdin drains any saved native step before the runtime exits.
  await Promise.all(clients.map(client => client.close()));
}

for (const [phase, { count, milliseconds }] of [...phases].sort(([a], [b]) => a.localeCompare(b))) {
  note(`PHASE ${phase} x${count}: ${milliseconds} ms`);
}
const forbidden = FORBIDDEN.filter(phase => phases.has(phase));
if (!failure && forbidden.length) failure = new Error(`slow-path phases appeared: ${forbidden.join(', ')}`);
note(JSON.stringify({
  network, status: failure ? 'failed' : 'passed', prover: prover.runtime ? 'runtime-w8' : 'stock-bb',
  totalSeconds: Number(((performance.now() - started) / 1000).toFixed(2)), steps,
  phases: Object.fromEntries(phases), stages: [...stages].sort(), balances: final ?? null,
  ...(failure ? { error: failure.message } : {}),
}));
note(failure ? `FAIL blinded desktop check: ${failure.message}` : `PASS blinded desktop: 10,000 + 5,000 Public deposits, Go private, alice -> bob two-coin and bob -> carol one-coin private handovers with automatic claims, Go public, whole-set deposit, restart. Retained local network: ${network}.`);
await new Promise(resolve => log.end(resolve));
if (failure) process.exitCode = 1;
