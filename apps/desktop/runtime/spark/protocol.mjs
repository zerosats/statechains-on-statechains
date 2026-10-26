// Wallet identity comes from the process's locked profile, never the webview.
const FIELDS = { refresh: [], publicDeposit: ['amountSat'], goPrivate: ['leaf'], preview: ['side', 'address', 'amountSat'],
  publicSend: ['address', 'amountSat'], privateSend: ['address', 'coins'], goPublic: ['coin'] };
// Incognito payments name the one or two picked coins instead of an amount.
const INCOGNITO_PREVIEW = ['side', 'address', 'coins'];
// A move to Incognito names a whole bill Public holds, or a bill value the SSP makes.
const GO_PRIVATE_AMOUNT = ['amountSat'];
const COIN = /^[a-f0-9]{32}$/;
const PUBLIC_ADDRESS = /^spark-regtest:0[23][a-f0-9]{64}$/;
const INCOGNITO_ADDRESS = /^zark-regtest:[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const matches = (value, pattern) => typeof value === 'string' && pattern.test(value);

// Exactly { id, action, args } with the action's exact argument names. `poll-`
// ids belong to the runtime's own refreshes and are never admitted from the UI.
function envelope(line) {
  let request;
  try { request = JSON.parse(line); } catch { throw new Error('Invalid Spark request'); }
  const invalid = () => Object.assign(new Error('Invalid Spark request'), { requestId: typeof request?.id === 'string' && /^[\w-]{1,128}$/.test(request.id) ? request.id : undefined });
  if (!request || Array.isArray(request) || typeof request !== 'object' || !/^[\w-]{1,128}$/.test(request.id ?? '') ||
      typeof request.id !== 'string' || request.id.startsWith('poll-') || typeof request.action !== 'string' || !Object.hasOwn(FIELDS, request.action) ||
      Object.keys(request).some(k => !['id', 'action', 'args'].includes(k)) ||
      !request.args || Array.isArray(request.args) || typeof request.args !== 'object') throw invalid();
  const args = request.args;
  const names = request.action === 'preview' && args.side === 'incognito' ? INCOGNITO_PREVIEW
    : request.action === 'goPrivate' && Object.hasOwn(args, 'amountSat') ? GO_PRIVATE_AMOUNT : FIELDS[request.action];
  if (Object.keys(args).length !== names.length || Object.keys(args).some(k => !names.includes(k))) throw invalid();
  return { request, invalid };
}

/** The actions the backend accepts. */
export function parseRequest(line) {
  const { request, invalid } = envelope(line);
  const { action, args } = request;
  // Whole sats only; the backend applies the exact denomination and answers
  // other amounts with a displayable `amount` error.
  if (Object.hasOwn(args, 'amountSat') && !(Number.isSafeInteger(args.amountSat) && args.amountSat >= 1 && args.amountSat <= 1_000_000)) throw invalid();
  if (action === 'preview' && args.side !== 'public' && args.side !== 'incognito') throw invalid();
  const side = action === 'preview' ? args.side : action === 'publicSend' ? 'public' : action === 'privateSend' ? 'incognito' : null;
  if (side && !matches(args.address, side === 'public' ? PUBLIC_ADDRESS : INCOGNITO_ADDRESS)) throw invalid();
  if (Object.hasOwn(args, 'coins') && !(Array.isArray(args.coins) && args.coins.length >= 1 && args.coins.length <= 2 &&
      args.coins.every(coin => matches(coin, COIN)) && new Set(args.coins).size === args.coins.length)) throw invalid();
  if (action === 'goPrivate' && Object.hasOwn(args, 'leaf') && !matches(args.leaf, UUID)) throw invalid();
  if (action === 'goPublic' && !matches(args.coin, COIN)) throw invalid();
  return request;
}

// Synthetic display data for visual QA; preview mode never starts a worker.
// The bills match the browser mock's funded wallet, so preview screens pick the same coins.
const at = 1761040000000;
const PREVIEW_LEAVES = [10000, 10000, 10000, 10000, 10000, 10000, 2000, 2000];
const PREVIEW_COINS = [['00112233445566778899aabbcc7d8e9f', 10000], ['ffeeddccbbaa99887766554433aa11bb', 5000],
  ['0a1b2c3d4e5f60718293a4b5c6d7e8f9', 2000], ['9f8e7d6c5b4a39281706f5e4d3c2b1a0', 2000]];
export const previewSnapshot = {
  connected: true,
  blinded: {
    network: 'preview', profile: 'wallet', status: 'ready', blocked: null, operation: null, denominationSat: 2000,
    public: { address: `spark-regtest:02${'a'.repeat(64)}`, totalSat: 64000,
      leaves: PREVIEW_LEAVES.map((amountSat, i) => ({ id: `12345678-1234-4123-8123-12345678900${i}`, amountSat, available: true })),
      incoming: [] },
    incognito: { address: `zark-regtest:${'b'.repeat(64)}`, totalSat: 19000,
      coins: PREVIEW_COINS.map(([id, amountSat]) => ({ id, amountSat, state: 'available', origin: 'public', canSend: true, canGoPublic: true })),
      incoming: [] },
    activity: [
      { id: 'preview-go-private', side: 'transition', kind: 'goPrivate', label: 'Moved to Incognito', amountSat: 10000, state: 'complete', at: at + 120_000, counterparty: null },
      { id: 'preview-received', side: 'public', kind: 'publicReceived', label: 'Received payment', amountSat: 10000, state: 'complete', at: at + 60_000, counterparty: 'bob' },
      { id: 'preview-deposit-2', side: 'public', kind: 'deposit', label: 'Deposited to Public', amountSat: 19000, state: 'complete', at: at + 30_000, counterparty: null },
      { id: 'preview-deposit-1', side: 'public', kind: 'deposit', label: 'Deposited to Public', amountSat: 19000, state: 'complete', at, counterparty: null },
    ],
  },
};
