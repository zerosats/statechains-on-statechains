import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseRequest, previewSnapshot } from './protocol.mjs';
import { SparkWorker } from './worker.mjs';

const MAX_REQUEST_BYTES = 16_384;

// Bound each line before buffering/parsing it, and recover at its next newline.
async function* requestLines(input) {
  let pieces = [];
  let length = 0;
  let oversized = false;
  for await (const chunk of input) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    let offset = 0;
    while (offset < bytes.length) {
      const newline = bytes.indexOf(10, offset);
      const end = newline === -1 ? bytes.length : newline;
      const part = bytes.subarray(offset, end);
      length += part.length;
      if (length > MAX_REQUEST_BYTES) { oversized = true; pieces = []; }
      else if (!oversized) pieces.push(part);
      if (newline === -1) break;
      yield oversized ? null : Buffer.concat(pieces, length).toString('utf8').replace(/\r$/, '');
      pieces = []; length = 0; oversized = false; offset = newline + 1;
    }
  }
  if (length) yield oversized ? null : Buffer.concat(pieces, length).toString('utf8');
}

export async function runSparkBackend({ input = process.stdin, output = process.stdout, env = process.env, signals = process, Worker = SparkWorker } = {}) {
  let worker, stopping = false, failure, timer, polling, active = false, pollSequence = 0;
  const polls = new Set();
  // The worker streams typed `stage`/`progress` events itself, so this runtime
  // adds no progress labels and replies with documented error codes.
  const unavailable = { errorCode: 'unavailable' };
  const stop = () => { stopping = true; input.destroy(); };
  const emit = event => {
    if (polls.delete(event.id)) { event = { ...event }; delete event.id; }
    if (!output.writable || output.destroyed) return;
    const encoded = `${JSON.stringify(event)}\n`;
    if (Buffer.byteLength(encoded) + output.writableLength > 4_000_000) { stop(); return; }
    output.write(encoded);
  };
  for (const signal of ['SIGINT', 'SIGTERM']) signals.on(signal, stop);
  output.on('error', stop);
  try {
    if (env.ZARK_PREVIEW !== '1') {
      try { worker = new Worker({ env, emit }); }
      catch { failure = 'Spark prototype could not start. Use ./run-wallet.sh with the pinned toolchain and retained regtest setup.'; emit({ error: failure, ...unavailable }); }
      if (worker) timer = setInterval(() => {
        if (active || polling || stopping) return;
        const id = `poll-${++pollSequence}`;
        polls.add(id);
        polling = worker.request({ id, action: 'refresh', args: {} }).catch(() => {}).finally(() => { polls.delete(id); polling = null; });
      }, 5000);
    }
    for await (const line of requestLines(input)) {
      if (stopping) break;
      let request;
      try {
        request = parseRequest(line);
        if (failure) { emit({ id: request.id, error: failure, ...unavailable }); continue; }
        if (env.ZARK_PREVIEW === '1') {
          emit({ id: request.id, snapshot: previewSnapshot,
            ...(request.action !== 'refresh' ? { error: 'Preview only. Launch the regtest session to run this action.', ...unavailable } : {}) });
          continue;
        }
        active = true;
        await polling;
        await worker.request(request);
      } catch (error) {
        // An unparsed request has no worker outcome; a parsed one failed in the worker.
        emit({ id: request?.id ?? error.requestId, error: error.message, ...(request ? unavailable : {}) });
      } finally { active = false; }
    }
  } finally {
    // EOF and signals close admission, then drain the saved native operation.
    clearInterval(timer);
    await polling;
    await worker?.close();
    for (const signal of ['SIGINT', 'SIGTERM']) signals.off(signal, stop);
    output.off('error', stop);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) await runSparkBackend();
