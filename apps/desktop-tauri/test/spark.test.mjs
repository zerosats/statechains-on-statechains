import test from 'node:test';
import assert from 'node:assert/strict';
import { addressValid, shortAddress, sendAmount, depositAmount, depositBills, homeView, sendView, togglePick, MAX_SEND_BILLS } from '../ui/spark/model.js';
import { walletState, intentRequest, reviewState, progressText, cashBills } from '../ui/spark/adapter.js';
import { initialModel, applyEvent, beginAction, endAction } from '../ui/model.js';
import { mockWallet } from '../ui/mock/fixtures.js';

const blindedSnapshot = blinded => ({ connected: true, blinded });
function appWith(snapshot, extra = {}) {
  const model = initialModel();
  applyEvent(model, { snapshot }, true);
  return { model, running: true, side: 'public', info: { preview: false }, ...extra };
}

test('blinded snapshots normalise into the wallet state', () => {
  const blinded = mockWallet('funded');
  blinded.public.leaves.push({ id: 'busy', amountSat: 10000, available: false });
  blinded.incognito.coins.push({ id: 'out', amountSat: 2000, state: 'sending', canSend: false, canGoPublic: false });
  const state = walletState(blindedSnapshot(blinded));
  assert.equal(state.public.enterable.length, 8);
  assert.equal(state.incognito.sendable.length, 4);
  assert.equal(state.incognito.exitable.length, 4);
  assert.deepEqual(state.incognito.coins.at(-1), { id: 'out', amountSat: 2000, canSend: false }, 'every bill shows, sendable or not');
  assert.deepEqual(state.activity.map(item => item.side),
    ['Incognito', 'Public', 'Incognito', 'Public', 'Public ↔ Incognito', 'Public ↔ Incognito', 'Public']);
  assert.equal(walletState(blindedSnapshot({ ...blinded, status: 'blocked' })).pending, true);
  assert.equal(walletState(blindedSnapshot({ ...blinded, operation: { kind: 'goPublic', state: 'interrupted' } })).pending, true);
  assert.equal(walletState({ connected: true }), null);
});

test('Public withdraws to Incognito as the most cash in the fewest bills', () => {
  const amounts = total => cashBills(total).map(bill => bill.amountSat);
  assert.deepEqual(amounts(64000), [10000, 10000, 10000, 10000, 10000, 10000, 2000, 2000]);
  assert.deepEqual(amounts(7000), [5000, 2000]);
  assert.deepEqual(amounts(6000), [2000, 2000, 2000], 'not 5,000 with 1,000 left');
  assert.deepEqual(amounts(16500), [10000, 2000, 2000, 2000]);
  assert.deepEqual(amounts(17000), [10000, 5000, 2000]);
  assert.deepEqual(amounts(1999), []);
  assert.equal(new Set(cashBills(64000).map(bill => bill.id)).size, 8);
  assert.deepEqual(cashBills(19000).map(bill => bill.id), ['cash-10000-0', 'cash-5000-0', 'cash-2000-0', 'cash-2000-1'],
    'bills are numbered within their value');
  const split = mockWallet('funded');
  split.public.leaves = [{ id: 'a', amountSat: 3500, available: true }, { id: 'b', amountSat: 3500, available: true }];
  assert.deepEqual(walletState(blindedSnapshot(split)).public.enterable.map(bill => bill.amountSat), [5000, 2000]);
});

test('intents map to the blinded actions', () => {
  const address = `zark-regtest:${'c'.repeat(64)}`;
  const coins = ['a'.repeat(32)];
  assert.deepEqual(intentRequest('send', { side: 'incognito', address, amountSat: 1, coins }), { action: 'privateSend', args: { address, coins } });
  assert.deepEqual(intentRequest('review', { side: 'incognito', address, amountSat: 1, coins }), { action: 'preview', args: { side: 'incognito', address, coins } });
  assert.deepEqual(intentRequest('send', { side: 'public', address, amountSat: 64000 }).action, 'publicSend');
  assert.deepEqual(intentRequest('review', { side: 'public', address, amountSat: 1 }), { action: 'preview', args: { side: 'public', address, amountSat: 1 } });
  assert.deepEqual(intentRequest('goPrivate', { id: 'leaf' }), { action: 'goPrivate', args: { leaf: 'leaf' } });
  assert.deepEqual(intentRequest('goPrivate', { id: 'cash-5000-1' }), { action: 'goPrivate', args: { amountSat: 5000 } });
  assert.deepEqual(intentRequest('goPublic', { id: 'coin' }), { action: 'goPublic', args: { coin: 'coin' } });
  assert.deepEqual(intentRequest('deposit', { amountSat: 64000 }), { action: 'publicDeposit', args: { amountSat: 64000 } });
  assert.throws(() => intentRequest('swap'));
});

test('a review confirms only the matching send form', () => {
  assert.deepEqual(reviewState({ preview: { side: 'incognito', amountSat: 64000, changeSat: 0, feeSat: 0, inputs: ['x'] } }),
    { side: 'incognito', amountSat: 64000, changeSat: 0, feeSat: 0, inputs: ['x'] });
  assert.equal(reviewState({}), null);

  const app = appWith(blindedSnapshot(mockWallet('funded')), { side: 'incognito' });
  const [first, second] = app.model.snapshot.blinded.incognito.coins.map(coin => coin.id);
  const form = { address: `zark-regtest:${'c'.repeat(64)}`, picked: [first] };
  let view = sendView(app, form);
  assert.deepEqual([view.coins, view.amountSat, view.target, view.canSend, view.matches], [[first], 10000, 'ready', true, false]);
  assert.equal(sendView(app, { ...form, picked: ['gone'] }).canSend, false, 'a sendable bill must be picked');
  assert.deepEqual(sendView(app, { ...form, picked: [first, second] }).amountSat, 15000, 'two bills add up');
  app.model.preview = { side: 'incognito', amountSat: 10000, changeSat: 0, feeSat: 0, inputs: [first] };
  assert.equal(sendView(app, form).matches, true);
  assert.equal(sendView(app, { ...form, picked: [first, second] }).matches, false, 'another bill needs a new review');
  view = sendView(app, { ...form, address: app.model.snapshot.blinded.incognito.address });
  assert.deepEqual([view.target, view.canSend], ['own', false], 'not to itself');
  view = sendView(app, { ...form, address: `spark-regtest:03${'3'.repeat(64)}` });
  assert.deepEqual([view.target, view.canSend], ['other', false], 'addresses are side specific');
  assert.equal(sendView({ ...app, side: 'public' }, { address: 'lnbcrt20u1p', amount: '2000' }).target, 'lightning');
});

test('picking keeps at most two bills and toggles them off again', () => {
  const form = { picked: [] };
  assert.equal(MAX_SEND_BILLS, 2);
  assert.equal(togglePick(form, 'a', MAX_SEND_BILLS), true);
  assert.equal(togglePick(form, 'b', MAX_SEND_BILLS), true);
  assert.equal(togglePick(form, 'c', MAX_SEND_BILLS), false);
  assert.deepEqual(form.picked, ['a', 'b']);
  togglePick(form, 'a', MAX_SEND_BILLS);
  assert.deepEqual(form.picked, ['b']);
});

test('sends and deposits defer denominations to the backend', () => {
  const blinded = walletState(blindedSnapshot(mockWallet('funded')));
  assert.equal(sendAmount('2000'), 2000);
  for (const bad of ['0', '', '1e3', '-1', '1.0']) assert.equal(sendAmount(bad), null);
  assert.equal(depositAmount(blinded, '5000'), 5000);
  assert.equal(depositAmount(blinded, '1.5'), null);
  assert.equal(depositAmount(null, '10000'), null);
  assert.deepEqual(depositBills(19000), [10000, 5000, 2000, 2000]);
  assert.deepEqual(depositBills(5000), [5000]);
  for (const bad of [1000, 17000, 64000, null]) assert.equal(depositBills(bad), null);
});

test('home view follows the design states', () => {
  const funded = homeView(appWith(blindedSnapshot(mockWallet('funded'))));
  assert.deepEqual([funded.balanceSat, funded.funded, funded.sendDisabled, funded.link.label, funded.footer],
    [64000, true, false, 'Move to Incognito', 'one · Regtest']);
  const empty = homeView(appWith(blindedSnapshot(mockWallet('empty'))));
  assert.deepEqual([empty.funded, empty.sendDisabled, empty.receiveDisabled, empty.link.label, empty.link.sheet], [false, true, false, 'Add test funds', 'sparkDeposit']);
  const pending = homeView(appWith(blindedSnapshot(mockWallet('pending'))));
  assert.deepEqual([pending.reconciliation, pending.sendDisabled, pending.receiveDisabled, pending.link.disabled], [true, true, false, true]);
  const incognito = homeView(appWith(blindedSnapshot(mockWallet('funded')), { side: 'incognito' }));
  assert.deepEqual([incognito.bills.map(coin => coin.amountSat), incognito.link.label, incognito.link.disabled], [[10000, 5000, 2000, 2000], 'Move to Public', false]);
  const none = homeView(appWith(blindedSnapshot(mockWallet('empty')), { side: 'incognito' }));
  assert.deepEqual([none.bills, none.link.disabled], [[], true]);
});

test('v2 states: disconnected, incoming payments and background claims', () => {
  const offline = mockWallet('disconnected');
  const app = appWith({ ...blindedSnapshot(offline), connected: false });
  const view = homeView(app);
  assert.match(view.notice, /not reachable/);
  assert.deepEqual([view.reconciliation, view.receiveDisabled, view.link.disabled], [false, true, true]);
  const incognito = homeView({ ...app, side: 'incognito' });
  assert.deepEqual([incognito.balanceSat, incognito.receiveDisabled, incognito.sendDisabled], [19000, false, true]);

  const incoming = appWith(blindedSnapshot(mockWallet('incoming')), { side: 'incognito' });
  assert.equal(homeView(incoming).status, 'Receiving payment…');
  assert.equal(homeView({ ...incoming, side: 'public' }).status, '');
  applyEvent(incoming.model, { stage: { operation: 'claim', step: 'propose', label: 'Refreshing key shares', index: 0, count: 5 } }, false);
  assert.equal(homeView(incoming).status, 'Refreshing key shares…');
  const interrupted = mockWallet('funded');
  interrupted.incognito.incoming = [{ id: 'e'.repeat(32), amountSat: 64000, state: 'interrupted' }];
  interrupted.operation = { kind: 'claim', stage: null, coin: 'e'.repeat(32), state: 'interrupted' };
  const stuck = homeView(appWith(blindedSnapshot(interrupted), { side: 'incognito' }));
  assert.deepEqual([stuck.status, stuck.reconciliation, stuck.sendDisabled], ['', true, true]);

  assert.equal(progressText({ stage: { label: 'Waiting for another window…' } }), 'Waiting for another window…');
});

test('receive addresses are specific to the selected side and shortened only for display', () => {
  const spark = `spark-regtest:02${'a'.repeat(64)}`, zark = `zark-regtest:${'b'.repeat(64)}`;
  assert.equal(addressValid(spark, 'public'), true);
  assert.equal(addressValid(spark, 'incognito'), false);
  assert.equal(addressValid(zark, 'incognito'), true);
  assert.equal(addressValid(zark, 'public'), false);
  assert.equal(shortAddress(`spark-regtest:03${'3'.repeat(64)}`), 'spark-regtest:033333…33333333');
  assert.equal(shortAddress(`spark-regtest:03${'3'.repeat(64)}`, 17, 4), 'spark-regtest:033…3333');
  assert.equal(shortAddress('spark-regtest:03'), 'spark-regtest:03');
});

test('blinded stages, previews and error codes reach the model', () => {
  const model = initialModel();
  beginAction(model, 'goPrivate');
  applyEvent(model, { stage: { operation: 'goPrivate', label: 'Proving receive', index: 4, count: 7 } }, false);
  assert.equal(progressText(model), 'Proving receive…');
  applyEvent(model, { id: 'ui-1', error: 'Wrong amount', errorCode: 'amount' }, true);
  assert.deepEqual([model.error, model.errorCode], ['Wrong amount', 'amount']);
  endAction(model);
  assert.equal(model.stage, null);
  assert.equal(progressText(model), 'Working…');
  applyEvent(model, { id: 'ui-2', preview: { side: 'public', amountSat: 64000 } }, true);
  assert.deepEqual([model.preview.amountSat, model.error, model.errorCode], [64000, null, null]);
  applyEvent(model, { stage: { operation: 'claim', label: 'Claiming' } }, false);
  applyEvent(model, { snapshot: blindedSnapshot(mockWallet('funded')) }, false);
  assert.equal(model.stage, null, 'a background claim ends with its snapshot');
});
