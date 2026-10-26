// View-model for the Spark screens: what each screen shows and which actions
// it allows. Backends still check every request before recording an intent.
import { walletState, reviewState, progressText } from './adapter.js';

export const sparkState = app => walletState(app.model.snapshot);

/** An Incognito send moves at most two whole bills. */
export const MAX_SEND_BILLS = 2;
/** Test deposits the backend accepts: one bill, or 19,000 for the whole set. */
const DEPOSIT_BILLS = { 10000: [10000], 5000: [5000], 2000: [2000], 19000: [10000, 5000, 2000, 2000] };

const wholeSats = text => {
  if (typeof text !== 'string' || !/^\d{1,16}$/.test(text)) return null;
  const value = Number(text);
  return Number.isSafeInteger(value) && value > 0 ? value : null;
};

export function addressValid(address, side) {
  return typeof address === 'string' && (side === 'public' ? /^spark-regtest:0[23][a-f0-9]{64}$/.test(address)
    : side === 'incognito' && /^zark-regtest:[a-f0-9]{64}$/.test(address));
}

/** Shows the start and end of a long address in a field that is not being edited. */
export const shortAddress = (value, head = 20, tail = 8) =>
  (value.length > head + tail + 1 ? `${value.slice(0, head)}…${value.slice(-tail)}` : value);

/** Payment amount in whole sats. The backend explains rejected amounts itself. */
export const sendAmount = wholeSats;

/** Deposit amount in whole sats; the backend refuses amounts that are not a denomination. */
export function depositAmount(state, text) {
  return state ? wholeSats(text) : null;
}

/** True while no new wallet action may start. Every one needs the Spark regtest stack. */
export function actionsBlocked(app, state = sparkState(app)) {
  return app.model.busy || !app.model.loaded || !app.running || !state || state.pending || !state.connected;
}

const NOTICES = {
  disconnected: 'Spark regtest is not reachable. Start it with scripts/spark-dev.sh up.',
};

/** Home caption: the running action, else a background claim, else payments still arriving. */
function statusText(app, wallet) {
  if (app.model.busy || app.model.stage) return progressText(app.model);
  return wallet?.incoming ? 'Receiving payment…' : '';
}

export function homeView(app) {
  const state = sparkState(app), side = app.side, wallet = state?.[side], blocked = actionsBlocked(app, state);
  const incognito = side === 'incognito';
  const notice = state && !state.connected ? 'disconnected' : null;
  const sendable = wallet?.sendable.length ?? 0;
  const link = incognito
    ? { label: 'Move to Public', sheet: 'sparkExit', disabled: blocked || !wallet?.exitable.length }
    : state?.public.enterable.length
      ? { label: 'Move to Incognito', sheet: 'sparkEnter', disabled: blocked }
      : { label: 'Add test funds', sheet: 'sparkDeposit', disabled: blocked };
  return {
    side,
    balanceSat: wallet?.totalSat ?? 0,
    funded: (wallet?.totalSat ?? 0) > 0,
    bills: incognito ? wallet?.coins ?? [] : [],
    sendDisabled: blocked || !sendable,
    receiveDisabled: app.model.busy || !wallet?.address,
    link,
    reconciliation: Boolean(state?.pending),
    notice: notice && NOTICES[notice],
    status: statusText(app, wallet),
    error: app.model.busy ? null : app.model.error,
    footer: `${state?.profile ?? 'Wallet'} · ${app.info.preview ? 'Preview' : 'Regtest'}`,
  };
}

/** The picked bills that are still sendable, in wallet order. */
function pickedCoins(state, form) {
  const picked = new Set(form.picked ?? []);
  return (state?.incognito.sendable ?? []).filter(coin => picked.has(coin.id)).map(coin => coin.id);
}

/** Toggles one bill, keeping at most `limit` picked. Returns false when the limit refuses it. */
export function togglePick(form, id, limit = Infinity) {
  const picked = form.picked ?? [];
  if (picked.includes(id)) form.picked = picked.filter(item => item !== id);
  else if (picked.length < limit) form.picked = [...picked, id];
  else return false;
  return true;
}

/** What the pasted destination is, for the field's label and the Continue step. */
function destination(address, side, own) {
  if (!address) return 'empty';
  if (own) return 'own';
  if (addressValid(address, side)) return 'ready';
  if (addressValid(address, side === 'public' ? 'incognito' : 'public')) return 'other';
  if (side === 'public' && /^ln(bc|tb|bcrt)[0-9a-z]+$/i.test(address)) return 'lightning';
  return 'invalid';
}

/** Send screens: the form's validity and whether the latest review matches it. */
export function sendView(app, form) {
  const state = sparkState(app), side = app.side, address = form.address.trim();
  const coins = side === 'incognito' ? pickedCoins(state, form) : null;
  const byId = new Map((state?.incognito.sendable ?? []).map(coin => [coin.id, coin.amountSat]));
  const amountSat = coins ? coins.reduce((sum, id) => sum + byId.get(id), 0) : sendAmount(form.amount);
  const target = destination(address, side, address === state?.[side]?.address);
  const valid = target === 'ready' && (coins ? coins.length > 0 : amountSat !== null);
  const review = reviewState(app.model);
  const blocked = actionsBlocked(app, state);
  const matches = review && review.side === side &&
    (coins ? review.inputs.join() === coins.join() : review.amountSat === amountSat);
  return {
    side, address, amountSat, coins, review, target, sent: form.sent,
    canSend: !blocked && valid,
    matches: Boolean(matches),
  };
}

const RECEIVED = new Set(['privateReceived', 'publicReceived']);

/** Payments that finished arriving since `seen` was last updated; adds them to `seen`. */
export function newArrivals(state, seen) {
  const fresh = (state?.activity ?? []).filter(item => RECEIVED.has(item.kind) && item.state === 'complete' && !seen.has(item.key));
  for (const item of fresh) seen.add(item.key);
  return fresh;
}

/** The bills one deposit creates, or null for an amount the backend refuses. */
export const depositBills = amountSat => DEPOSIT_BILLS[amountSat] ?? null;
