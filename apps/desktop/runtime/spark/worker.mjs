import { spawn } from 'node:child_process';
import path from 'node:path';
import { emitTiming } from '../timing.mjs';
import { forwardDiagnostics } from './diagnostics.mjs';

export const TEST_NAME = 'private_transfer::real_fixture::live_receive::desktop::serve_blinded_wallet_regtest';
const MARKER = 'ZARK_DESKTOP ';
const FAILURE = 'Spark regtest worker stopped. Reopen the same session; retained operations must be reconciled before new work.';

/** One profile client on the serialized local test network. Closing stdin
 * drains the current operation. Never kill it on a UI timeout or window close. */
export class SparkWorker {
  constructor({ env, emit, spawnProcess = spawn, diagnostics = emitTiming }) {
    const binary = env.ZARK_SPARK_DESKTOP_BINARY;
    if (!path.isAbsolute(binary ?? '') || binary.includes('\0')) throw new Error('Build the Spark desktop worker with ./run-wallet.sh first.');
    this.emit = emit;
    this.pending = new Map();
    this.buffer = '';
    this.closed = false;
    this.child = spawnProcess(binary, [TEST_NAME, '--exact', '--ignored', '--nocapture', '--test-threads=1'], {
      env: { ...env, ZARK_SPARK_DESKTOP: 'blinded-regtest' }, stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.done = new Promise(resolve => {
      this.child.once('error', () => { this.fail(); resolve(); });
      this.child.once('close', () => { if (!this.closed || this.pending.size) this.fail(); resolve(); });
    });
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', chunk => this.consume(chunk));
    // Native diagnostics and private paths are never forwarded to the webview;
    // fixed-format timing lines may reach stderr on explicit opt-in.
    if (env.ZARK_SPARK_FORWARD_TIMINGS === '1') forwardDiagnostics(this.child.stderr, diagnostics);
    else this.child.stderr.resume();
    this.child.stdin.on('error', () => this.fail());
  }
  fail() {
    if (this.failed) return;
    this.failed = true;
    this.emit({ error: FAILURE });
    for (const { reject } of this.pending.values()) reject(new Error(FAILURE));
    this.pending.clear();
    this.child.stdin.end();
  }
  consume(chunk) {
    this.buffer += chunk;
    if (Buffer.byteLength(this.buffer) > 4_000_000) return this.fail();
    let newline;
    while ((newline = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      const marker = line.indexOf(MARKER);
      if (marker < 0) continue; // Rust's test runner also prints its status.
      let value;
      try { value = JSON.parse(line.slice(marker + MARKER.length)); } catch { this.fail(); return; }
      if (!value || typeof value !== 'object' || Array.isArray(value)) { this.fail(); return; }
      // The native shell applies a typed display projection, including Spark
      // fields. The worker's dedicated marker is never used for diagnostic data.
      const reply = value.id ? this.pending.get(value.id) : null;
      if (value.id && !reply) { this.fail(); return; }
      this.emit(value);
      if (reply) { this.pending.delete(value.id); reply.resolve(); }
    }
  }
  request(request) {
    if (this.failed || this.closed || this.pending.has(request.id)) return Promise.reject(new Error(FAILURE));
    return new Promise((resolve, reject) => {
      this.pending.set(request.id, { resolve, reject });
      this.child.stdin.write(`${JSON.stringify(request)}\n`);
    });
  }
  async close() {
    this.closed = true;
    this.child.stdin.end();
    await this.done;
  }
}
