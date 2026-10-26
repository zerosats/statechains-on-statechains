import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Readable, Writable } from 'node:stream';
import { parseRequest, previewSnapshot } from './spark/protocol.mjs';
import { SparkWorker, TEST_NAME } from './spark/worker.mjs';
import { runSparkBackend } from './spark/main.mjs';
import { forwardDiagnostics, safeDiagnostic } from './spark/diagnostics.mjs';

const request = (action, args = {}, id = 'ui-1') => ({ id, action, args });
const line = (...args) => JSON.stringify(request(...args));
function output() {
  let bytes = '';
  return { stream: new Writable({ write(chunk, _encoding, done) { bytes += chunk; done(); } }), events: () => bytes.trim().split('\n').filter(Boolean).map(JSON.parse) };
}

test('worker ignores runner diagnostics and drains instead of killing an active operation', async () => {
  const child = new EventEmitter();
  child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.stdin = new PassThrough();
  child.kill = () => assert.fail('must drain');
  const emitted = [];
  const worker = new SparkWorker({ env: { ZARK_SPARK_DESKTOP_BINARY: '/fixture/test' }, emit: value => emitted.push(value), spawnProcess: (_file, args, options) => {
    assert.ok(args.includes('--ignored')); assert.equal(options.env.ZARK_SPARK_DESKTOP, 'blinded-regtest'); return child;
  } });
  const pending = worker.request(request('refresh'));
  child.stderr.write('private diagnostic');
  child.stdout.write('running 1 test\ntest worker ... ZARK_DESKTOP {"id":"ui-1","progress":"Done"}\n');
  await pending;
  assert.deepEqual(emitted, [{ id: 'ui-1', progress: 'Done' }]);
  const closed = worker.close();
  assert.equal(child.stdin.writableEnded, true);
  child.emit('close', 0);
  await closed;
});

test('unexpected worker reply fails closed without replaying a request', async () => {
  const child = new EventEmitter();
  child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.stdin = new PassThrough();
  const emitted = [];
  const worker = new SparkWorker({ env: { ZARK_SPARK_DESKTOP_BINARY: '/fixture/test' }, emit: value => emitted.push(value), spawnProcess: () => child });
  const pending = worker.request(request('pay', { actor: 'alice', recipient: 'bob', amountSat: 33000 }));
  const rejected = assert.rejects(pending, /retained operations/);
  child.stdout.write('ZARK_DESKTOP {"id":"wrong"}\n');
  await rejected;
  assert.equal(emitted.length, 1);
  await assert.rejects(worker.request(request('refresh', {}, 'ui-2')));
  child.emit('close', 1); await worker.close();
});

test('Spark runtime drains an authorized request after SIGTERM and rejects further admission', async () => {
  const signals = new EventEmitter(), input = new PassThrough(), out = output();
  let finish, started, closed = false;
  const ready = new Promise(resolve => { started = resolve; });
  const running = runSparkBackend({ input, output: out.stream, signals, env: {}, Worker: class {
    request() { started(); return new Promise(resolve => { finish = resolve; }); }
    async close() { closed = true; }
  } });
  input.write(line('refresh') + '\n'); await ready;
  signals.emit('SIGTERM');
  assert.equal(closed, false);
  finish();
  // Destroyed input ends admission; the saved request is already drained.
  await running.catch(error => { assert.equal(error.code, 'ERR_STREAM_PREMATURE_CLOSE'); });
  assert.equal(closed, true);
});

const PUBLIC = `spark-regtest:02${'a'.repeat(64)}`, INCOGNITO = `zark-regtest:${'b'.repeat(64)}`;
const LEAF = '12345678-1234-4123-8123-123456789abc', COIN = 'c'.repeat(32);
function fakeChild() {
  const child = new EventEmitter();
  child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.stdin = new PassThrough();
  return child;
}

test('wire admits exactly the documented actions and argument formats', () => {
  for (const [action, args] of [
    ['refresh', {}],
    ['publicDeposit', { amountSat: 64000 }], ['publicDeposit', { amountSat: 1 }], ['publicDeposit', { amountSat: 1_000_000 }],
    ['goPrivate', { leaf: LEAF }], ['goPrivate', { amountSat: 5000 }],
    ['preview', { side: 'public', address: PUBLIC, amountSat: 64000 }],
    ['preview', { side: 'incognito', address: INCOGNITO, coins: [COIN] }],
    // Other whole amounts reach the backend, which answers with errorCode "amount".
    ['publicSend', { address: `spark-regtest:03${'1'.repeat(64)}`, amountSat: 33000 }],
    ['privateSend', { address: INCOGNITO, coins: [COIN] }], ['privateSend', { address: INCOGNITO, coins: [COIN, 'd'.repeat(32)] }],
    ['goPublic', { coin: COIN }],
  ]) assert.deepEqual(parseRequest(line(action, args)), request(action, args));
});

test('wire rejects legacy actions, extra or mistyped args and cross-side addresses', () => {
  const amounts = [0, -1, 1.5, '64000', null, 1_000_001, Number.MAX_SAFE_INTEGER];
  for (const [action, args] of [
    ['refresh', { amountSat: 64000 }],
    ['publicDeposit', {}], ['publicDeposit', { amountSat: 64000, address: PUBLIC }],
    ...amounts.map(amountSat => ['publicDeposit', { amountSat }]),
    ...amounts.map(amountSat => ['publicSend', { address: PUBLIC, amountSat }]),
    ...[[], [COIN, COIN], [COIN, 'd'.repeat(32), 'e'.repeat(32)], ['C'.repeat(32)], [LEAF], COIN, null].map(coins => ['privateSend', { address: INCOGNITO, coins }]),
    ['privateSend', { address: INCOGNITO, amountSat: 64000 }], ['privateSend', { address: INCOGNITO, coins: [COIN], amountSat: 64000 }],
    ['goPrivate', { leaf: LEAF.toUpperCase() }], ['goPrivate', { leaf: COIN }], ['goPrivate', { leaf: 7 }], ['goPrivate', { coin: LEAF }],
    ['goPrivate', { leaf: LEAF, amountSat: 5000 }], ['goPrivate', { amountSat: 0 }], ['goPrivate', { amountSat: '5000' }], ['goPrivate', {}],
    ['preview', { side: 'public', address: INCOGNITO, amountSat: 64000 }],
    ['preview', { side: 'incognito', address: PUBLIC, coins: [COIN] }],
    ['preview', { side: 'incognito', address: INCOGNITO, amountSat: 64000 }],
    ['preview', { side: 'public', address: PUBLIC, coins: [COIN] }],
    ['preview', { side: 'regular', address: PUBLIC, amountSat: 64000 }],
    ['preview', { side: ['public'], address: PUBLIC, amountSat: 64000 }],
    ['preview', { side: 'public', address: PUBLIC }],
    ['preview', { side: 'public', address: PUBLIC, amountSat: 64000, feeSat: 0 }],
    ['publicSend', { address: INCOGNITO, amountSat: 64000 }],
    ['publicSend', { address: `spark-regtest:04${'a'.repeat(64)}`, amountSat: 64000 }],
    ['publicSend', { address: `spark-regtest:02${'A'.repeat(64)}`, amountSat: 64000 }],
    ['publicSend', { address: `${PUBLIC}a`, amountSat: 64000 }],
    ['publicSend', { address: PUBLIC, amountSat: 64000, profile: 'bob' }],
    ['privateSend', { address: PUBLIC, coins: [COIN] }],
    ['privateSend', { address: `zark-regtest:${'b'.repeat(63)}`, coins: [COIN] }],
    ['privateSend', { address: [INCOGNITO], coins: [COIN] }],
    ['goPublic', { coin: 'c'.repeat(64) }], ['goPublic', { coin: 'C'.repeat(32) }], ['goPublic', { coin: LEAF }], ['goPublic', {}],
    ...['send', 'plan', 'deposit', 'enter', 'exit', 'claim', 'withdraw', '__proto__', 'constructor', 'toString'].map(action => [action, {}]),
  ]) assert.throws(() => parseRequest(line(action, args)), error => error.requestId === 'ui-1', `${action} ${JSON.stringify(args)}`);
  for (const args of [[], null, 'refresh', 7]) {
    assert.throws(() => parseRequest(JSON.stringify({ id: 'ui-1', action: 'refresh', args })), error => error.requestId === 'ui-1');
  }
  assert.throws(() => parseRequest(JSON.stringify({ ...request('refresh'), profile: 'bob' })), error => error.requestId === 'ui-1');
  assert.throws(() => parseRequest(line('refresh', {}, 'poll-1')));
  for (const bad of [null, 'null', '[]', '{}', 'not json', JSON.stringify({ id: 'bad id', action: 'refresh', args: {} })]) {
    assert.throws(() => parseRequest(bad), error => error.requestId === undefined);
  }
});

test('worker runs the blinded desktop test with its own marker', async () => {
  assert.equal(TEST_NAME, 'private_transfer::real_fixture::live_receive::desktop::serve_blinded_wallet_regtest');
  const child = fakeChild();
  let spawned;
  const worker = new SparkWorker({ env: { ZARK_SPARK_DESKTOP_BINARY: '/fixture/test', ZARK_SPARK_DESKTOP: 'inherited' },
    emit: () => {}, spawnProcess: (file, args, options) => { spawned = { file, args, marker: options.env.ZARK_SPARK_DESKTOP }; return child; } });
  assert.deepEqual(spawned, { file: '/fixture/test', args: [TEST_NAME, '--exact', '--ignored', '--nocapture', '--test-threads=1'], marker: 'blinded-regtest' });
  const closed = worker.close(); child.emit('close', 0); await closed;
});

test('preview never starts a worker and never offers spendable actions', async () => {
  const out = output();
  await runSparkBackend({ env: { ZARK_PREVIEW: '1' }, output: out.stream, signals: new EventEmitter(),
    input: Readable.from([[line('refresh'), line('privateSend', { address: INCOGNITO, coins: [COIN] }, 'ui-2'), line('deposit', { amountSat: 64000 }, 'ui-3')].join('\n') + '\n']),
    Worker: class { constructor() { throw new Error('must not start'); } } });
  const [refresh, send, legacy] = out.events();
  assert.deepEqual(refresh, { id: 'ui-1', snapshot: previewSnapshot });
  assert.equal(send.errorCode, 'unavailable');
  assert.match(send.error, /Preview only/);
  assert.deepEqual(legacy, { id: 'ui-3', error: 'Invalid Spark request' });
  const { blinded } = previewSnapshot;
  const sum = items => items.reduce((total, item) => total + item.amountSat, 0);
  assert.equal(blinded.public.totalSat, sum(blinded.public.leaves));
  assert.equal(blinded.incognito.totalSat, sum(blinded.incognito.coins));
  assert.ok(parseRequest(line('preview', { side: 'public', address: blinded.public.address, amountSat: 64000 })));
  assert.ok(parseRequest(line('preview', { side: 'incognito', address: blinded.incognito.address, coins: [blinded.incognito.coins[0].id] })));
  assert.ok(parseRequest(line('goPrivate', { leaf: blinded.public.leaves[0].id })));
  assert.ok(parseRequest(line('goPublic', { coin: blinded.incognito.coins[0].id })));
});

test('runtime relays worker stages without Node progress labels', async () => {
  const input = new PassThrough(), out = output(), seen = [];
  const stage = { operation: 'goPrivate', step: 'identity', label: 'Joint identity', index: 2, count: 7, expectedMs: 16000 };
  const running = runSparkBackend({ input, output: out.stream, signals: new EventEmitter(), env: {}, Worker: class {
    constructor({ emit }) { this.emit = emit; }
    async request(next) {
      seen.push(next.action);
      if (next.action === 'goPublic') throw new Error('Spark regtest worker stopped.');
      this.emit({ stage });
      this.emit({ id: next.id, snapshot: { blinded: { status: 'ready' } } });
    }
    async close() {}
  } });
  input.end([line('goPrivate', { leaf: LEAF }), line('publicDeposit', { amountSat: 64000 }, 'ui-2'),
    line('deposit', { amountSat: 64000 }, 'ui-3'), line('goPublic', { coin: COIN }, 'ui-4')].join('\n') + '\n');
  await running;
  const events = out.events();
  assert.deepEqual(seen, ['goPrivate', 'publicDeposit', 'goPublic']);
  assert.ok(events.every(event => !Object.hasOwn(event, 'progress')));
  assert.deepEqual(events.slice(0, 2), [{ stage }, { id: 'ui-1', snapshot: { blinded: { status: 'ready' } } }]);
  assert.deepEqual(events.at(-2), { id: 'ui-3', error: 'Invalid Spark request' });
  assert.deepEqual(events.at(-1), { id: 'ui-4', error: 'Spark regtest worker stopped.', errorCode: 'unavailable' });
});

test('runtime keeps the idle refresh poll and strips its runtime id', async t => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  const input = new PassThrough(), out = output(), seen = [];
  const running = runSparkBackend({ input, output: out.stream, signals: new EventEmitter(), env: {}, Worker: class {
    constructor({ emit }) { this.emit = emit; }
    async request(next) { seen.push(next); this.emit({ id: next.id, snapshot: { blinded: { status: 'ready' } } }); }
    async close() {}
  } });
  t.mock.timers.tick(5000);
  await new Promise(setImmediate);
  input.end();
  await running;
  assert.deepEqual(seen, [{ id: 'poll-1', action: 'refresh', args: {} }]);
  assert.deepEqual(out.events(), [{ snapshot: { blinded: { status: 'ready' } } }]);
});

test('native stderr filter passes only fixed-format timing lines', async () => {
  const safe = ['ZARK_STAGE_TIMING {"phase":"identity_mpc","milliseconds":812}', 'ZARK_EXIT_TIMING {"phase":"share_release","milliseconds":40}',
    'Real Spark ownership prove completed in 6.2s'];
  const unsafe = ['Real Spark ownership prove: /Users/someone/work/job', 'ZARK_STAGE_TIMING {"phase":"identity_mpc","milliseconds":812,"secret":"x"}',
    'ZARK_STAGE_TIMING {"phase":"Identity","milliseconds":1}', 'ZARK_STAGE_TIMING {"phase":"identity_mpc","milliseconds":-1}',
    ' ZARK_STAGE_TIMING {"phase":"a","milliseconds":1}', 'ZARK_STAGE_TIMING {"phase":"a","milliseconds":1} trailing',
    `ZARK_STAGE_TIMING {"phase":"${'a'.repeat(65)}","milliseconds":1}`, 'Real Spark ownership witness completed in 1.0s',
    'ZARK_PROOF_TIMING {"prove_seconds":1}', 'thread panicked: private share 0123abcd', ''];
  for (const value of safe) assert.equal(safeDiagnostic(value), true, value);
  for (const value of unsafe) assert.equal(safeDiagnostic(value), false, value);
  const stream = new PassThrough(), forwarded = [];
  forwardDiagnostics(stream, value => forwarded.push(value));
  const text = [...unsafe, ...safe].join('\n') + '\n';
  for (let i = 0; i < text.length; i += 7) stream.write(text.slice(i, i + 7));
  // An overlong line is dropped whole, including a safe-looking tail in a later chunk.
  stream.write(`${'x'.repeat(300)}\n`);
  stream.write('y'.repeat(300));
  stream.write(`${safe[0]}\n${safe[1]}\n`);
  await new Promise(setImmediate);
  assert.deepEqual(forwarded, [...safe, safe[1]]);
});

test('worker forwards timing lines only on explicit opt-in', async () => {
  for (const flag of [undefined, '0', '1']) {
    const child = fakeChild(), forwarded = [];
    const worker = new SparkWorker({ env: { ZARK_SPARK_DESKTOP_BINARY: '/fixture/test', ...(flag ? { ZARK_SPARK_FORWARD_TIMINGS: flag } : {}) },
      emit: () => {}, diagnostics: value => forwarded.push(value), spawnProcess: () => child });
    child.stderr.write('private diagnostic /tmp/job\nZARK_STAGE_TIMING {"phase":"receive_tweak","milliseconds":9}\n');
    await new Promise(setImmediate);
    assert.deepEqual(forwarded, flag === '1' ? ['ZARK_STAGE_TIMING {"phase":"receive_tweak","milliseconds":9}'] : []);
    const closed = worker.close(); child.emit('close', 0); await closed;
  }
});
