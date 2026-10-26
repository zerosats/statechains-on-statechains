// Public screens (Paper "zarkxspark", New design P01–P09, E02) and the shared
// Receive and Add test funds screens. Spark is the only route this build pays;
// Bitcoin and Lightning appear as cards only.
import { h } from '../components.js';
import { sats } from '../model.js';
import { routeCard, badge } from './art.js';
import { sparkState, sendView, depositAmount, depositBills, actionsBlocked, shortAddress } from './model.js';
import {
  stage, backButton, title, primary, secondary, textLink, note, field, amount, amountInput, addressArea, row,
  place, run, reviewAndSend, busyLabel, ACTION, BELOW, GAP, SECONDARY, FIELD_END, ROW, AMOUNT, headerEnd, centred,
} from './page.js';
import { incognitoSendScreen } from './cash.js';
import { resultScreen } from './result.js';

const CARD_HEIGHT = 202, QR = 280;

/** The Spark card across the column; `mark` puts a status badge on its lower right corner. */
const sparkCard = (top, mark) => [routeCard('spark', [220, top, 320, CARD_HEIGHT], 'single'),
  mark ? badge(mark, 518, top + CARD_HEIGHT - 22) : null];

export function sparkSheetState(kind) {
  return { amount: kind === 'sparkDeposit' ? '19000' : '', address: '', picked: [], step: null,
    copied: false, qr: '', sent: false, working: false, bills: [] };
}

const ADDRESS_ERRORS = new Set(['invalid_address', 'unknown_recipient']);
const DESTINATION_LABEL = {
  empty: 'Spark address or Lightning invoice',
  ready: 'Spark address',
  lightning: 'Lightning invoice · not available yet',
  other: 'Incognito address · switch to Incognito',
  own: 'Your own address · use another wallet',
  invalid: 'Not a Spark address',
};

export function sparkSendSheet(app) {
  return app.side === 'incognito' ? incognitoSendScreen(app) : publicSendScreen(app);
}

/** Back steps within a screen before leaving it; returns false to leave. */
export function sparkSendBack(app) {
  const form = app.sheetState;
  if (form.sent || !form.step || form.step === 'destination' || form.step === 'pick') return false;
  form.step = app.side === 'incognito' ? 'pick' : 'destination';
  app.model.error = null;
  app.clearReview();
  app.render();
  return true;
}

function publicSendScreen(app) {
  const form = app.sheetState, view = sendView(app, form);
  form.step ??= 'destination';
  if (form.step === 'destination') return destinationStep(app, form, view);
  const params = { side: 'public', address: view.address, amountSat: view.amountSat };
  const to = row('To', shortAddress(view.address, 17, 4), ROW);
  const resultCard = centred(headerEnd(), AMOUNT, CARD_HEIGHT);
  if (form.sent) return resultScreen(app, 'Payment sent', view.amountSat, routeCard('spark', [220, resultCard, 320, CARD_HEIGHT], 'single leaving'));
  if (form.working) {
    return stage('Sending payment', backButton(app), title('Sending payment.'),
      sparkCard(resultCard, 'pending'),
      amount(view.amountSat, AMOUNT), to,
      primary(busyLabel(app.model, 'Sending…'), ACTION, { disabled: true }));
  }
  const failed = app.model.error;
  const editAddress = ADDRESS_ERRORS.has(app.model.errorCode);
  const recover = () => {
    app.model.error = null; app.model.errorCode = null;
    if (editAddress) form.step = 'destination';
    app.render();
  };
  return stage(failed ? 'Couldn’t send' : 'Send payment', backButton(app), title(failed ? 'Couldn’t send.' : 'Send payment.'),
    sparkCard(centred(headerEnd(), AMOUNT - GAP - 84, CARD_HEIGHT)),
    field('Spark address', AMOUNT - GAP - 84, { value: shortAddress(view.address), height: 84 }),
    amount(null, AMOUNT, { input: amountInput(form, app, () => app.clearReview()) }),
    failed ? note(failed, ROW + 14, 'danger selectable') : row('Fee', `${sats(view.review?.feeSat ?? 0)} sats`, ROW),
    failed
      ? primary(editAddress ? 'Edit address' : 'Edit amount', ACTION, { onClick: recover })
      : primary(view.amountSat ? `Send ${sats(view.amountSat)} sats` : 'Enter an amount', ACTION, {
        disabled: !view.canSend, onClick: () => reviewAndSend(app, params, form, () => sendView(app, form)),
      }));
}

function destinationStep(app, form, view) {
  const advance = () => {
    if (sendView(app, form).target === 'ready') form.step = 'amount';
  };
  const paste = async () => {
    try { form.address = (await navigator.clipboard.readText()).trim(); }
    catch { app.model.error = 'Paste the address into the field with ⌘V or Ctrl+V.'; }
    advance(); app.render();
  };
  const bad = !['empty', 'ready'].includes(view.target);
  const cards = centred(headerEnd(), FIELD_END - 103, 62 + CARD_HEIGHT);
  return stage('Send payment', backButton(app), title('Send payment.'),
    routeCard('lightning', [224, cards, 312, 197]),
    routeCard('spark', [220, cards + 62, 320, CARD_HEIGHT], 'front'),
    field(DESTINATION_LABEL[view.target], FIELD_END - 103, {
      height: 103, tone: bad ? 'bad' : '',
      input: addressArea(form, app, { placeholder: 'Paste here', onEdit: () => { app.model.error = null; advance(); } }),
    }),
    app.model.error ? note(app.model.error, FIELD_END + 6, 'danger') : null,
    secondary('Scan QR code', SECONDARY, { disabled: true }),
    primary('Paste from clipboard', ACTION, { disabled: actionsBlocked(app), onClick: paste }));
}

export async function sparkReceiveLoad(app) {
  const form = app.sheetState, address = sparkState(app)?.[app.side]?.address;
  if (!address) return;
  try { form.qr = await app.qr(address); if (app.sheetState === form) app.render(); } catch { /* Copy remains available. */ }
}

export function sparkReceiveSheet(app) {
  const incognito = app.side === 'incognito', form = app.sheetState;
  const address = sparkState(app)?.[app.side]?.address ?? '';
  const fieldTop = ACTION - GAP - 137;
  return stage(incognito ? 'Receive cash' : 'Receive sats', backButton(app),
    title(incognito ? 'Receive cash.' : 'Receive sats.', incognito ? 'Share your Incognito address.' : undefined),
    place(h('div', { class: 'z-qr' }, form.qr ? h('img', { src: form.qr, alt: 'Receive address QR code' }) : null),
      centred(headerEnd(incognito), fieldTop, QR), 380 - QR / 2, QR),
    field(incognito ? 'Incognito address' : 'Spark address', fieldTop, { value: address, height: 137 }),
    primary(form.copied ? 'Address copied' : 'Copy address', ACTION, {
      disabled: !address, onClick: async () => { await app.copy(address); form.copied = true; app.render(); },
    }),
    textLink('Add test funds', BELOW, () => app.openSheet('sparkDeposit'), { disabled: actionsBlocked(app) }));
}

const billList = bills => bills.map(value => sats(value)).join(' · ');

export function sparkDepositSheet(app) {
  const form = app.sheetState, incognito = app.side === 'incognito';
  const amountSat = depositAmount(sparkState(app), form.amount), bills = depositBills(amountSat);
  const busy = app.model.busy;
  // The detail keeps room for two lines above the action; the incognito hint always wraps to two.
  const detailTop = ACTION - GAP - 42, hintTop = detailTop - 4 - (incognito ? 42 : 21);
  const amountTop = hintTop - 12 - (incognito ? 90 : 62);
  const detail = app.model.error && !busy ? note(app.model.error, detailTop, 'danger selectable')
    : bills ? note(`Adds ${bills.length} note${bills.length > 1 ? 's' : ''}: ${billList(bills)}`, detailTop)
      : note('Enter 10,000, 5,000 or 2,000, or 19,000 for one of each plus a second 2,000.', detailTop, 'danger');
  const deposit = () => run(app, 'deposit', { amountSat }, () => app.finishTransition('public'));
  const input = busy ? null : amountInput(form, app, () => { app.model.error = null; });
  const label = busy ? busyLabel(app.model, 'Adding…') : incognito ? 'Add to Public' : 'Add test funds';
  return stage('Add test funds', backButton(app),
    title('Add test funds.', incognito ? 'Funds arrive in Public first.' : undefined),
    sparkCard(centred(headerEnd(incognito), amountTop, CARD_HEIGHT)),
    amount(amountSat, amountTop, { label: incognito ? 'Amount' : undefined, input }),
    note(incognito ? 'After funding, move your balance into Incognito notes.' : 'Test funds only · no monetary value', hintTop),
    detail,
    primary(label, ACTION, { disabled: actionsBlocked(app) || !bills, onClick: deposit }));
}
