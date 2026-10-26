// Contract with the blinded backend: events recorded from a live regtest run
// (test/fixtures/blinded-live.json) through the adapter and view-model, and the
// UI's requests through the runtime's parser. Re-record after an interface change.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { walletState, intentRequest, progressText } from '../ui/spark/adapter.js';
import { homeView, sendView } from '../ui/spark/model.js';
import { initialModel, applyEvent, beginAction, endAction } from '../ui/model.js';
import { mockWallet } from '../ui/mock/fixtures.js';
import { parseRequest, previewSnapshot } from '../../desktop/runtime/spark/protocol.mjs';

const live = JSON.parse(readFileSync(new URL('./fixtures/blinded-live.json', import.meta.url), 'utf8'));

// Field names and value kinds, recursively; arrays by their first element.
function shape(value) {
  if (Array.isArray(value)) return value.length ? [shape(value[0])] : [];
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, shape(value[key])]));
  return value === null ? 'null' : typeof value;
}
const snapshotShape = blinded => {
  const s = shape(blinded);
  // Nullable or possibly-empty parts are compared where both sides have them.
  for (const key of ['blocked', 'operation']) delete s[key];
  for (const side of ['public', 'incognito']) delete s[side].incoming;
  delete s.incognito.coins;
  s.activity = s.activity.map(item => ({ ...item, counterparty: 'nullable' }));
  return s;
};

test('the mock and preview data have the live snapshot shape', () => {
  const real = snapshotShape(live.bobFinal.snapshot.blinded);
  const withCoin = live.previewReply.event.snapshot.blinded;
  assert.deepEqual(shape(mockWallet('funded').incognito.coins[0]), shape(withCoin.incognito.coins[0]));
  assert.deepEqual(snapshotShape(mockWallet('funded')), real);
  assert.deepEqual(snapshotShape(previewSnapshot.blinded), real);
  assert.deepEqual(Object.keys(live.bobFinal.snapshot).sort(), Object.keys(previewSnapshot).sort());
});

test('live snapshots render through the adapter and view-model', () => {
  const app = { model: initialModel(), running: true, side: 'public', info: { preview: false } };
  applyEvent(app.model, live.emptyRefresh, true);
  let view = homeView(app);
  assert.deepEqual([view.balanceSat, view.sendDisabled, view.receiveDisabled, view.link.sheet, view.notice], [0, true, false, 'sparkDeposit', null]);

  applyEvent(app.model, live.bobFinal, true);
  const state = walletState(app.model.snapshot);
  assert.deepEqual([state.profile, state.connected, state.pending, state.public.totalSat, state.public.sendable.length], ['bob', true, false, 128000, 2]);
  assert.deepEqual(state.activity.map(item => [item.label, item.side]),
    [['Moved to Public', 'Public ↔ Incognito'], ['Received payment', 'Public'], ['Received payment', 'Incognito']]);
  view = homeView(app);
  assert.deepEqual([view.balanceSat, view.sendDisabled, view.footer], [128000, false, 'bob · Regtest']);

  applyEvent(app.model, live.aliceFinal, true);
  assert.deepEqual(walletState(app.model.snapshot).activity.map(item => item.label),
    ['Sent payment', 'Deposited to Public', 'Sent payment', 'Moved to Incognito', 'Deposited to Public']);
});

test('live stages show as progress and clear with the background snapshot', () => {
  const model = initialModel();
  beginAction(model, 'goPrivate');
  for (const [operation, event] of Object.entries(live.stages)) {
    applyEvent(model, event, false);
    assert.equal(event.stage.operation, operation);
    assert.ok(Number.isInteger(event.stage.count) && Number.isInteger(event.stage.expectedMs), operation);
    assert.equal(progressText(model), `${event.stage.label}…`);
  }
  endAction(model);
  applyEvent(model, live.stages.claim, false);
  applyEvent(model, live.backgroundSnapshot, false);
  assert.equal(model.stage, null);
});

test('live refusals reach the model with their codes', () => {
  for (const [code, { event }] of Object.entries(live.errors)) {
    const model = initialModel();
    applyEvent(model, event, true);
    assert.deepEqual([model.errorCode, model.error], [code, event.error]);
  }
  assert.deepEqual(Object.keys(live.errors).sort(), ['amount', 'invalid_address', 'no_coins', 'unknown_recipient']);
});

test('the UI builds the exact requests the live run sent, and the runtime admits them', () => {
  const { requests } = live;
  const built = {
    refresh: { action: 'refresh', args: {} },
    preview: intentRequest('review', requests.preview.args),
    publicDeposit: intentRequest('deposit', requests.publicDeposit.args),
    goPrivate: intentRequest('goPrivate', { id: requests.goPrivate.args.leaf }),
    privateSend: intentRequest('send', { side: 'incognito', ...requests.privateSend.args }),
    publicSend: intentRequest('send', { side: 'public', ...requests.publicSend.args }),
    goPublic: intentRequest('goPublic', { id: requests.goPublic.args.coin }),
  };
  for (const [action, request] of Object.entries(requests)) {
    assert.deepEqual(built[action], { action: request.action, args: request.args }, action);
    assert.deepEqual(parseRequest(JSON.stringify({ id: 'ui-1', ...built[action] })).args, request.args, action);
  }
});

test('a live preview confirms the matching send form only', () => {
  const { request, event } = live.previewReply;
  const app = { model: initialModel(), running: true, side: request.args.side, info: { preview: false } };
  applyEvent(app.model, event, true);
  const form = { address: request.args.address, picked: request.args.coins };
  assert.deepEqual([sendView(app, form).canSend, sendView(app, form).matches], [true, true]);
  assert.equal(sendView(app, { ...form, picked: ['f'.repeat(32)] }).matches, false);
  assert.equal(event.preview.recipient, 'bob');
});
