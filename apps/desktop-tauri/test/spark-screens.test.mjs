import test from 'node:test';
import assert from 'node:assert/strict';
import { PREVIEW_SCREENS, applyPreviewScreen } from '../ui/spark/preview.js';
import { sparkSheetState } from '../ui/spark/sheets.js';
import { activityRows, activityTime } from '../ui/spark/views.js';
import { homeView, newArrivals, sendView, sparkState } from '../ui/spark/model.js';
import { initialModel, applyEvent } from '../ui/model.js';
import { createMockBridge } from '../ui/mock/bridge.js';
import { RECIPIENT } from '../ui/mock/fixtures.js';
import { intentRequest } from '../ui/spark/adapter.js';

async function mockApp(screen = 'public-home') {
  const bridge = createMockBridge(new URLSearchParams({ screen, stepMs: '0' }));
  const app = { model: initialModel(), running: true, side: 'public', sparkPage: 'wallet',
    info: await bridge.appInfo(), sheet: null, sheetState: {}, renders: 0, render() { this.renders += 1; },
    openSheet(kind, fields = {}) { this.sheet = kind; this.sheetState = { ...sparkSheetState(kind), ...fields }; } };
  await bridge.onWallet(({ event, isReply }) => applyEvent(app.model, event, isReply));
  await bridge.perform('refresh', {});
  return { app, bridge };
}

async function screenApp(name) {
  const { app } = await mockApp(name);
  applyPreviewScreen(app, name);
  return app;
}

test('every design screen fixture opens its side, page and sheet', async () => {
  // One per New design artboard plus the extra interface states in preview.js.
  assert.equal(Object.keys(PREVIEW_SCREENS).length, 33);
  for (const [name, screen] of Object.entries(PREVIEW_SCREENS)) {
    const { app } = await mockApp(name);
    assert.equal(applyPreviewScreen(app, name), true, name);
    assert.equal(app.side, screen.side, name);
    assert.equal(app.sparkPage, screen.page ?? 'wallet', name);
    assert.equal(app.sheet, screen.sheet ?? null, name);
    assert.equal(app.renders, 1, name);
  }
  const { app } = await mockApp();
  assert.equal(applyPreviewScreen(app, 'public-04'), false);
});

test('fixture states drive the view-model the screens render from', async () => {
  const ready = await screenApp('incognito-ready');
  const view = sendView(ready, ready.sheetState);
  assert.deepEqual([view.target, view.amountSat, view.canSend], ['ready', 12000, true]);
  assert.deepEqual(ready.sheetState.bills.map(coin => coin.amountSat), [10000, 2000], 'the address step carries the picked bills');
  const wrong = await screenApp('incognito-wrong-address');
  assert.deepEqual([sendView(wrong, wrong.sheetState).target, sendView(wrong, wrong.sheetState).canSend], ['other', false]);
  const lightning = await screenApp('public-lightning');
  assert.equal(sendView(lightning, lightning.sheetState).target, 'lightning');
  const sent = await screenApp('public-sent');
  assert.equal(sendView(sent, sent.sheetState).sent, true);
  const pending = await screenApp('public-reconciliation');
  assert.equal(homeView(pending).reconciliation, true);
  const deposit = await screenApp('public-deposit');
  assert.equal(deposit.sheetState.amount, '19000', 'test funds default to the whole set');
});

test('a payment that finishes arriving is news once, naming the bill it made', async () => {
  for (const [side, amountSat] of [['incognito', 10000], ['public', 1500]]) {
    const bridge = createMockBridge(new URLSearchParams({ screen: `${side}-home`, stepMs: '0', arrive: side, arriveMs: '0' }));
    const app = { model: initialModel() };
    await bridge.onWallet(({ event, isReply }) => applyEvent(app.model, event, isReply));
    await bridge.perform('refresh', {});
    const seen = new Set();
    assert.equal(newArrivals(sparkState(app), seen).length, 3, 'earlier receipts only seed what has been seen');
    await bridge.start();
    await new Promise(resolve => setTimeout(resolve, 5));
    const [arrival, ...rest] = newArrivals(sparkState(app), seen);
    assert.deepEqual([rest, arrival.wallet, arrival.amountSat], [[], side, amountSat]);
    const coins = sparkState(app).incognito.coins;
    if (side === 'incognito') assert.equal(coins.at(-1).id, arrival.coin);
    else assert.equal(arrival.coin, null);
    assert.deepEqual(newArrivals(sparkState(app), seen), []);
  }
});

test('activity lists each side with every transfer and labels it as the design does', async () => {
  const app = await screenApp('public-activity');
  const state = sparkState(app);
  const publicRows = activityRows(state, 'public'), incognitoRows = activityRows(state, 'incognito');
  assert.deepEqual(publicRows.map(row => row.label),
    ['Payment sent', 'Payment received', 'Moved to Incognito', 'Moved to Incognito', 'Funds added']);
  assert.deepEqual(publicRows.map(row => row.sign), [-1, 1, -1, -1, 1]);
  assert.deepEqual(incognitoRows.map(row => [row.label, row.detail, row.sign]).slice(-2),
    [['Moved to Incognito', 'From Public', 1], ['Moved to Incognito', 'From Public', 1]]);
  const now = new Date(2026, 9, 23, 12, 0);
  assert.equal(activityTime(new Date(2026, 9, 22, 18, 0).getTime(), now), 'Yesterday');
  assert.match(activityTime(new Date(2026, 9, 23, 9, 18).getTime(), now), /09:18|9:18/);
});

test('the mock backend runs deposit, go private, private send and go public', async () => {
  const { app, bridge } = await mockApp('public-empty');
  const wallet = () => app.model.snapshot.blinded;
  await bridge.perform('publicDeposit', { amountSat: 17000 });
  assert.equal(app.model.errorCode, 'amount');
  await bridge.perform('publicDeposit', { amountSat: 19000 });
  assert.deepEqual(wallet().public.leaves.map(leaf => leaf.amountSat), [10000, 5000, 2000, 2000]);
  await bridge.perform('goPrivate', { leaf: wallet().public.leaves[0].id });
  assert.deepEqual([wallet().public.totalSat, wallet().incognito.totalSat], [9000, 10000]);
  const address = `zark-regtest:${'3'.repeat(64)}`;
  const coin = wallet().incognito.coins[0].id;
  await bridge.perform('preview', { side: 'incognito', address, coins: [coin, coin] });
  assert.equal(app.model.errorCode, 'no_coins');
  await bridge.perform('preview', { side: 'incognito', address, coins: [coin] });
  assert.deepEqual([app.model.preview.amountSat, app.model.preview.inputs, app.model.errorCode], [10000, [coin], null]);
  await bridge.perform('privateSend', { address, coins: [coin] });
  assert.equal(wallet().incognito.totalSat, 0);
  assert.deepEqual(wallet().activity.map(item => item.label),
    [...Array(4).fill('Deposited to Public'), 'Moved to Incognito', 'Sent payment']);
});

test('the mock pays any Public amount and withdraws cash bills through the SSP', async () => {
  const { app, bridge } = await mockApp('public-empty');
  const stages = [];
  await bridge.onWallet(({ event, isReply }) => { if (event.stage) stages.push(event.stage.step); applyEvent(app.model, event, isReply); });
  const wallet = () => app.model.snapshot.blinded;
  await bridge.perform('publicDeposit', { amountSat: 10000 });
  await bridge.perform('preview', { side: 'public', address: RECIPIENT.public, amountSat: 3500 });
  assert.deepEqual([app.model.preview.amountSat, app.model.preview.changeSat, app.model.errorCode], [3500, 6500, null]);
  stages.length = 0;
  await bridge.perform('publicSend', { address: RECIPIENT.public, amountSat: 3500 });
  assert.deepEqual(stages, ['swap', 'transfer', 'deliver']);
  assert.deepEqual(wallet().public.leaves.map(leaf => leaf.amountSat), [6500]);
  assert.equal(wallet().activity.at(-1).amountSat, 3500);

  stages.length = 0;
  await bridge.perform('goPrivate', { amountSat: 5000 });
  assert.equal(stages[1], 'swap', 'the SSP makes the bill');
  assert.deepEqual([wallet().public.totalSat, wallet().incognito.coins.map(coin => coin.amountSat)], [1500, [5000]]);
  await bridge.perform('goPrivate', { amountSat: 5000 });
  assert.equal(app.model.errorCode, 'no_leaves');
  await bridge.perform('goPrivate', { amountSat: 3000 });
  assert.equal(app.model.errorCode, 'amount');

  await bridge.perform('publicDeposit', { amountSat: 2000 });
  stages.length = 0;
  await bridge.perform('goPrivate', { amountSat: 2000 });
  assert.ok(!stages.includes('swap'), 'a held bill moves as-is');
  assert.equal(wallet().public.totalSat, 1500);
});

test('Make it cash withdraws only the picked notes, by value', async () => {
  const picking = await screenApp('public-go-private');
  const notes = sparkState(picking).public.enterable;
  const chosen = notes.filter(bill => picking.sheetState.picked.includes(bill.id));
  assert.deepEqual(chosen.map(bill => bill.amountSat), [10000, 10000, 2000], 'the fixture picks from both piles');
  const moving = await screenApp('public-going-private');
  assert.deepEqual(moving.sheetState.bills, notes, 'a running move keeps the whole fan');

  const { app, bridge } = await mockApp('public-empty');
  const wallet = () => app.model.snapshot.blinded;
  await bridge.perform('publicDeposit', { amountSat: 10000 });
  await bridge.perform('publicSend', { address: RECIPIENT.public, amountSat: 3500 });
  const planned = sparkState(app).public.enterable;
  assert.deepEqual(planned.map(bill => bill.id), ['cash-2000-0', 'cash-2000-1', 'cash-2000-2'], 'no Public leaf is a note yet');
  for (const bill of planned.slice(0, 2)) {
    const { action, args } = intentRequest('goPrivate', { id: bill.id });
    await bridge.perform(action, args);
    assert.equal(app.model.errorCode, null);
  }
  assert.deepEqual([wallet().public.totalSat, wallet().incognito.coins.map(coin => coin.amountSat)], [2500, [2000, 2000]]);
  assert.deepEqual(sparkState(app).public.enterable.map(bill => bill.id), ['cash-2000-0'], 'the unpicked note is still offered');
});

test('the mock follows interface v2 recipients, amounts and Go public steps', async () => {
  const { app, bridge } = await mockApp('public-empty');
  const stages = [];
  await bridge.onWallet(({ event, isReply }) => { if (event.stage) stages.push(event.stage); applyEvent(app.model, event, isReply); });
  const wallet = () => app.model.snapshot.blinded;
  await bridge.perform('publicDeposit', { amountSat: 10000 });
  for (const [address, code] of [[wallet().public.address, 'invalid_address'], [RECIPIENT.public.replace(/3$/, '4'), 'unknown_recipient']]) {
    await bridge.perform('preview', { side: 'public', address, amountSat: 10000 });
    assert.equal(app.model.errorCode, code);
  }
  await bridge.perform('preview', { side: 'public', address: RECIPIENT.public, amountSat: 32000 });
  assert.equal(app.model.errorCode, 'no_leaves');
  await bridge.perform('preview', { side: 'public', address: RECIPIENT.public, amountSat: 10000 });
  assert.equal(app.model.preview.recipient, 'two');
  assert.equal(app.model.preview.changeSat, 0);

  await bridge.perform('goPrivate', { leaf: wallet().public.leaves[0].id });
  stages.length = 0;
  await bridge.perform('goPublic', { coin: wallet().incognito.coins[0].id });
  assert.deepEqual(stages.map(stage => stage.step), ['self_handover', 'head', 'release', 'chain_gate', 'send', 'claim', 'finalize']);
  assert.ok(stages.every(stage => stage.count === 7 && !stage.label.endsWith('…')));

  const received = await mockApp('incognito-home');
  const steps = [];
  await received.bridge.onWallet(({ event, isReply }) => { if (event.stage) steps.push(event.stage.step); applyEvent(received.app.model, event, isReply); });
  await received.bridge.perform('goPublic', { coin: received.app.model.snapshot.blinded.incognito.coins[0].id });
  assert.equal(steps[0], 'head', 'a received coin skips the self-handover');

  const offline = await mockApp('public-disconnected');
  assert.equal(offline.app.model.snapshot.connected, false);
  await offline.bridge.perform('publicDeposit', { amountSat: 10000 });
  assert.equal(offline.app.model.errorCode, 'unavailable');
});

test('a blocked mock wallet refuses new operations', async () => {
  const { app, bridge } = await mockApp('public-reconciliation');
  await bridge.perform('publicSend', { address: `spark-regtest:03${'3'.repeat(64)}`, amountSat: 10000 });
  assert.equal(app.model.errorCode, 'blocked');
  assert.equal(app.model.snapshot.blinded.public.totalSat, 64000);
});
