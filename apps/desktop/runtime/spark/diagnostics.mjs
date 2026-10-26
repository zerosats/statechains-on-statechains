// Native worker stderr can contain private paths, payloads and error text. On
// explicit opt-in only fixed-format duration lines pass, byte for byte; every
// other line, including an overlong one, is dropped.
const SAFE = [
  /^ZARK_(STAGE|EXIT)_TIMING \{"phase":"[a-z_0-9]{1,64}","milliseconds":\d{1,12}\}$/,
  /^Real Spark ownership (execute|prove|verify) completed in [0-9.]{1,16}s$/,
];
const MAX_LINE = 256;

export const safeDiagnostic = line => typeof line === 'string' && line.length <= MAX_LINE && SAFE.some(pattern => pattern.test(line));

export function forwardDiagnostics(stream, write) {
  let pending = '', overflow = false;
  stream.setEncoding('utf8');
  stream.on('data', chunk => {
    let start = 0, newline;
    while ((newline = chunk.indexOf('\n', start)) >= 0) {
      const line = overflow ? null : pending + chunk.slice(start, newline);
      pending = ''; overflow = false; start = newline + 1;
      if (safeDiagnostic(line)) write(line);
    }
    if (overflow) return;
    pending += chunk.slice(start);
    if (pending.length > MAX_LINE) { pending = ''; overflow = true; }
  });
}
