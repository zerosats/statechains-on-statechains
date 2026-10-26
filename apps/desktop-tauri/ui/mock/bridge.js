// MOCK backend for running the UI in a plain browser (no Tauri). It speaks the
// blinded backend's interface with in-memory data.
// Query: ?screen=<preview fixture>&platform=macos|linux&stepMs=<ms per step>
//        &arrive=incognito|public&arriveMs=<ms after start>
import { mockWallet, totals, STEPS, RECIPIENT } from './fixtures.js';
import { previewScenario } from '../spark/preview.js';
import { depositBills } from '../spark/model.js';

const DEPOSIT_ERROR = { error: 'Deposit 10,000, 5,000 or 2,000 sats, or 19,000 for the whole set.', errorCode: 'amount' };
const CASH_ERROR = { error: 'Incognito holds cash bills. Move 10,000, 5,000 or 2,000 sats.', errorCode: 'amount' };
const DENOMINATIONS = [10000, 5000, 2000];
const EXACT_LEAVES = 4;

/** The worker's Public selection: the fewest leaves that add up exactly, else the fewest covering leaves. */
function select(leaves, amountSat) {
  const sum = items => items.reduce((total, item) => total + item.amountSat, 0);
  const sets = (items, size, start = 0) => size === 0 ? [[]]
    : items.slice(start).flatMap((item, i) => sets(items, size - 1, start + i + 1).map(rest => [item, ...rest]));
  const byId = [...leaves].sort((a, b) => a.id.localeCompare(b.id));
  for (let size = 1; size <= Math.min(EXACT_LEAVES, byId.length); size++) {
    const exact = sets(byId, size).find(set => sum(set) === amountSat);
    if (exact) return { items: exact, changeSat: 0 };
  }
  const largest = [...byId].sort((a, b) => b.amountSat - a.amountSat);
  let count = 0;
  while (count < largest.length && sum(largest.slice(0, count)) < amountSat) count++;
  if (sum(largest.slice(0, count)) < amountSat) return null;
  const covers = count > EXACT_LEAVES ? [largest.slice(0, count)] : sets(byId, count).filter(set => sum(set) >= amountSat);
  const items = covers.reduce((best, set) => sum(set) < sum(best) ? set : best);
  return { items, changeSat: sum(items) - amountSat };
}

export function createMockBridge(params) {
  const screen = params.get('screen');
  const wallet = mockWallet(previewScenario(screen));
  const stepMs = Number(params.get('stepMs') ?? 300);
  let handler = () => {}, at = 10;

  const connected = () => wallet.public.address !== null;
  const snapshot = () => ({ connected: connected(), blinded: structuredClone(wallet) });
  const emit = (event, isReply = false) => handler({ event, isReply, error: null });
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const record = (side, kind, label, amountSat, counterparty = null) =>
    wallet.activity.push({ id: `m${at++}`, side, kind, label, amountSat, state: 'complete', at: Date.now(), counterparty });
  const spendable = side => (side === 'public' ? wallet.public.leaves.filter(leaf => leaf.available) : wallet.incognito.coins.filter(item => item.canSend));
  const publicLeaf = amountSat => ({ id: crypto.randomUUID(), amountSat, available: true });

  // The swap step runs only when the SSP makes change.
  async function stages(operation, { from = 0, swap = true } = {}) {
    const steps = STEPS[operation].filter(([step], index) => index >= from && (swap || step !== 'swap'));
    const expectedMs = steps.length * stepMs;
    for (const [step, label] of steps) {
      const index = STEPS[operation].findIndex(([name]) => name === step);
      emit({ progress: label, stage: { operation, step, label, index, count: STEPS[operation].length, expectedMs } });
      await sleep(stepMs);
    }
  }

  /** The SSP swap: `items` leave Public, an `amountSat` leaf and the change arrive. */
  function swapLeaves(items, amountSat, changeSat) {
    for (const item of items) wallet.public.leaves.splice(wallet.public.leaves.indexOf(item), 1);
    const leaf = publicLeaf(amountSat);
    wallet.public.leaves.push(leaf);
    if (changeSat) wallet.public.leaves.push(publicLeaf(changeSat));
    return leaf;
  }

  // The same checks, in the same order, as the worker's preview. Incognito
  // payments name the picked coins; Public ones an amount.
  function payment(side, { address, amountSat, coins }) {
    if (side === 'public' && !(amountSat >= 1)) return { error: 'Enter an amount of at least 1 sat.', errorCode: 'amount' };
    if (address === wallet[side].address) return { error: "Use another wallet's address.", errorCode: 'invalid_address' };
    if (address !== RECIPIENT[side]) return { error: 'No wallet on this regtest network uses that address.', errorCode: 'unknown_recipient' };
    if (side === 'public') {
      return select(spendable(side), amountSat) ?? { error: 'Public does not hold enough to send that amount.', errorCode: 'no_leaves' };
    }
    const items = (coins ?? []).map(id => spendable(side).find(candidate => candidate.id === id));
    if (!items.length || items.length > 2 || new Set(coins).size !== items.length || items.some(item => !item)) {
      return { error: 'That Incognito coin is not available.', errorCode: 'no_coins' };
    }
    return { items, changeSat: 0 };
  }

  /** `?arrive=incognito|public` has the other profile pay this wallet `arriveMs` after start. */
  function scheduleArrival() {
    const side = params.get('arrive');
    if (side !== 'incognito' && side !== 'public') return;
    setTimeout(() => {
      const row = (id, kind, amountSat) => ({ id, side, kind, label: 'Received payment', amountSat, state: 'complete', at: Date.now(), counterparty: RECIPIENT.profile });
      if (side === 'incognito') {
        const id = hexId();
        wallet.incognito.coins.push({ id, amountSat: 10000, state: 'available', origin: 'received', canSend: true, canGoPublic: true });
        wallet.activity.push(row(`private-received-${id}`, 'privateReceived', 10000));
      } else {
        const leaf = publicLeaf(1500);
        wallet.public.leaves.push(leaf);
        wallet.activity.push(row(`public-received-${leaf.id}`, 'publicReceived', 1500));
      }
      totals(wallet);
      emit({ snapshot: snapshot() });
    }, Number(params.get('arriveMs') ?? 2500));
  }

  async function run(action, args) {
    if (action === 'refresh') return {};
    if (wallet.status === 'blocked') return { error: 'An operation needs reconciliation. New payments are paused.', errorCode: 'blocked' };
    if (!connected()) return { error: 'Spark regtest is not reachable. Start it with scripts/spark-dev.sh up.', errorCode: 'unavailable' };
    if (action === 'preview') {
      const checked = payment(args.side, args);
      if (!checked.items) return checked;
      const operation = args.side === 'public' ? 'publicSend' : 'privateSend', swap = checked.changeSat > 0;
      const steps = STEPS[operation].filter(([step]) => swap || step !== 'swap').length;
      const amountSat = checked.items.reduce((sum, item) => sum + item.amountSat, 0) - checked.changeSat;
      return { preview: { side: args.side, amountSat, changeSat: checked.changeSat, feeSat: 0, swap, inputs: checked.items.map(item => item.id),
        recipient: RECIPIENT.profile, expectedMs: steps * stepMs } };
    }
    if (action === 'publicSend') {
      const checked = payment('public', args);
      if (!checked.items) return checked;
      await stages(action, { swap: checked.changeSat > 0 });
      const sent = checked.changeSat ? [swapLeaves(checked.items, args.amountSat, checked.changeSat)] : checked.items;
      for (const item of sent) wallet.public.leaves.splice(wallet.public.leaves.indexOf(item), 1);
      record('public', 'publicSent', 'Sent payment', args.amountSat, RECIPIENT.profile);
      totals(wallet);
      return {};
    }
    if (action === 'privateSend') {
      const checked = payment('incognito', args);
      if (!checked.items) return checked;
      for (const item of checked.items) {
        await stages(action);
        wallet.incognito.coins.splice(wallet.incognito.coins.indexOf(item), 1);
        record('incognito', 'privateSent', 'Sent payment', item.amountSat, RECIPIENT.profile);
      }
      totals(wallet);
      return {};
    }
    if (action === 'publicDeposit') {
      const bills = depositBills(args.amountSat);
      if (!bills) return DEPOSIT_ERROR;
      for (const amountSat of bills) {
        await stages(action);
        wallet.public.leaves.push(publicLeaf(amountSat));
        record('public', 'deposit', 'Deposited to Public', amountSat);
      }
    } else if (action === 'goPrivate') {
      // Like an ATM: an existing bill moves as-is; otherwise the SSP makes one.
      let leaf, swap = false;
      if (Object.hasOwn(args, 'leaf')) {
        leaf = spendable('public').find(item => item.id === args.leaf && DENOMINATIONS.includes(item.amountSat));
        if (!leaf) return { error: 'That leaf is no longer available.', errorCode: 'no_leaves' };
      } else {
        if (!DENOMINATIONS.includes(args.amountSat)) return CASH_ERROR;
        leaf = spendable('public').find(item => item.amountSat === args.amountSat);
        if (!leaf) {
          const cover = select(spendable('public'), args.amountSat);
          if (!cover) return { error: 'Public does not hold enough for that bill.', errorCode: 'no_leaves' };
          swap = true;
          await stages(action, { swap });
          leaf = swapLeaves(cover.items, args.amountSat, cover.changeSat);
        }
      }
      if (!swap) await stages(action, { swap });
      wallet.public.leaves.splice(wallet.public.leaves.indexOf(leaf), 1);
      wallet.incognito.coins.push({ id: hexId(), amountSat: leaf.amountSat, state: 'available', origin: 'public', canSend: true, canGoPublic: true });
      record('transition', 'goPrivate', 'Moved to Incognito', leaf.amountSat);
    } else if (action === 'goPublic') {
      const item = wallet.incognito.coins.find(candidate => candidate.id === args.coin && candidate.canGoPublic);
      if (!item) return { error: 'That coin is no longer available.', errorCode: 'no_coins' };
      // Only a coin that entered from Public needs the self-handover step first.
      await stages(action, { from: item.origin === 'public' ? 0 : 1 });
      wallet.incognito.coins.splice(wallet.incognito.coins.indexOf(item), 1);
      wallet.public.leaves.push(publicLeaf(item.amountSat));
      record('transition', 'goPublic', 'Moved to Public', item.amountSat);
    }
    totals(wallet);
    return {};
  }

  return {
    appInfo: async () => ({ preview: true, previewScreen: screen, platform: params.get('platform') ?? 'macos' }),
    start: async () => scheduleArrival(),
    isRunning: async () => true,
    qrSvg: async value => mockQr(value),
    onWallet: async next => { handler = next; },
    async perform(action, args) {
      const id = `mock-${at++}`;
      const reply = await run(action, args);
      emit({ id, snapshot: snapshot(), ...reply }, true);
    },
  };
}

const hexId = () => [...crypto.getRandomValues(new Uint8Array(16))].map(byte => byte.toString(16).padStart(2, '0')).join('');

/** A deterministic QR-like pattern; not scannable. */
function mockQr(value) {
  const size = 29, cells = [];
  let seed = [...value].reduce((hash, char) => (hash * 31 + char.charCodeAt(0)) >>> 0, 7);
  const finder = (x, y) => [[0, 6], [size - 7, size - 1]].some(([lo, hi]) => x >= lo && x <= hi) &&
    [[0, 6], [size - 7, size - 1]].some(([lo, hi]) => y >= lo && y <= hi) && !(x >= size - 7 && y >= size - 7);
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    let dark;
    if (finder(x, y)) {
      const cx = x < 7 ? x : x - (size - 7), cy = y < 7 ? y : y - (size - 7);
      dark = cx === 0 || cx === 6 || cy === 0 || cy === 6 || (cx >= 2 && cx <= 4 && cy >= 2 && cy <= 4);
    } else {
      seed = (seed * 1103515245 + 12345) >>> 0;
      dark = (seed >>> 16) % 2 === 0;
    }
    if (dark) cells.push(`M${x} ${y}h1v1h-1z`);
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="${size}" height="${size}" fill="#fff"/><path d="${cells.join('')}" fill="#000"/></svg>`;
}
