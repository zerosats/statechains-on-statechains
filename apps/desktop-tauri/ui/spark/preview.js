// Visual QA fixtures: one per Paper "zarkxspark" New design artboard. Only
// applied in preview mode (ZARK_PREVIEW_SCREEN) or by the browser mock;
// `scenario` names the mock wallet data the screen expects.
import { sparkState } from './model.js';

const PUBLIC_TO = `spark-regtest:03${'3'.repeat(64)}`;
const INCOGNITO_TO = `zark-regtest:${'3'.repeat(64)}`;
// The funded mock wallet's 10,000 and first 2,000 bills, as artboard I01 picks them.
const PICKED = ['00112233445566778899aabbcc7d8e9f', '0a1b2c3d4e5f60718293a4b5c6d7e8f9'];
// Two of the six 10,000 notes and one of the two 2,000 notes the funded Public balance makes.
const CASH_PICKED = ['cash-10000-0', 'cash-10000-1', 'cash-2000-0'];
const SENDING = { busy: true, stage: { operation: 'publicSend', step: 'transfer', label: 'Sending on Spark' } };

const publicSend = (form = {}, model) => ({ side: 'public', sheet: 'sparkSend', form: { step: 'amount', address: PUBLIC_TO, amount: '2000', ...form }, model });
const cashSend = (form = {}, model) => ({ side: 'incognito', sheet: 'sparkSend', form: { step: 'address', picked: PICKED, ...form }, model });

export const PREVIEW_SCREENS = {
  'public-home': { side: 'public' },
  'incognito-home': { side: 'incognito' },
  'public-empty': { scenario: 'empty', side: 'public' },
  'public-reconciliation': { scenario: 'pending', side: 'public' },
  'public-send': { side: 'public', sheet: 'sparkSend' },
  'public-send-ready': publicSend(),
  'public-lightning': { side: 'public', sheet: 'sparkSend', form: { address: 'lnbcrt20u1pjexample' } },
  'public-sending': publicSend({ working: true }, SENDING),
  'public-sent': publicSend({ sent: true }),
  'public-payment-error': publicSend({}, { error: 'Insufficient liquidity for this amount. Try another amount.', errorCode: 'amount' }),
  'public-unknown-recipient': publicSend({ address: `spark-regtest:03${'4'.repeat(64)}` },
    { error: 'No wallet on this regtest network uses that address.', errorCode: 'unknown_recipient' }),
  'incognito-send': { side: 'incognito', sheet: 'sparkSend', form: { picked: PICKED } },
  'incognito-address': cashSend(),
  'incognito-ready': cashSend({ address: INCOGNITO_TO }),
  'incognito-wrong-address': cashSend({ address: PUBLIC_TO }),
  'incognito-sending': cashSend({ address: INCOGNITO_TO, working: true },
    { busy: true, stage: { operation: 'privateSend', step: 'prove_sender', label: 'Proving ownership' } }),
  'incognito-sent': cashSend({ address: INCOGNITO_TO, sent: true }),
  'public-receive': { side: 'public', sheet: 'sparkReceive' },
  'public-receive-copied': { side: 'public', sheet: 'sparkReceive', form: { copied: true } },
  'incognito-receive': { side: 'incognito', sheet: 'sparkReceive' },
  'public-deposit': { side: 'public', sheet: 'sparkDeposit' },
  'incognito-deposit': { side: 'incognito', sheet: 'sparkDeposit' },
  'public-activity': { side: 'public', page: 'activity' },
  'incognito-activity': { side: 'incognito', page: 'activity' },
  'public-empty-activity': { scenario: 'empty', side: 'public', page: 'activity' },
  'public-go-private': { side: 'public', sheet: 'sparkEnter', form: { picked: CASH_PICKED } },
  'public-no-leaves': { scenario: 'empty', side: 'public', sheet: 'sparkEnter' },
  'incognito-go-public': { side: 'incognito', sheet: 'sparkExit', form: { picked: PICKED } },
  // Interface v2 states without their own artboard; they reuse the screens above.
  'public-disconnected': { scenario: 'disconnected', side: 'public' },
  'incognito-incoming': { scenario: 'incoming', side: 'incognito' },
  'public-waiting': publicSend({ working: true }, { busy: true, stage: { operation: 'publicSend', step: 'waiting', label: 'Waiting for another window…' } }),
  'incognito-going-public': { side: 'incognito', sheet: 'sparkExit', form: { picked: PICKED, working: true, moving: 1, total: 2 },
    model: { busy: true, stage: { operation: 'goPublic', step: 'self_handover', label: 'Preparing the coin to leave', index: 0, count: 7, expectedMs: 19000 } } },
  'public-going-private': { side: 'public', sheet: 'sparkEnter', form: { picked: CASH_PICKED, working: true, moving: 2, total: 3 },
    model: { busy: true, stage: { operation: 'goPrivate', step: 'prove_receive', label: 'Proving receive', index: 5, count: 8, expectedMs: 24000 } } },
};

export const previewScenario = name => PREVIEW_SCREENS[name]?.scenario ?? 'funded';

/** Puts the app into a fixture's state. Returns false for an unknown name. */
export function applyPreviewScreen(app, name) {
  const screen = PREVIEW_SCREENS[name];
  if (!screen) return false;
  app.side = screen.side ?? 'public';
  if (screen.sheet) {
    app.openSheet(screen.sheet, screen.form);
    // Steps past the picker carry the picked bills, as Continue does; a running move carries the fan.
    const state = sparkState(app);
    if (app.side === 'incognito') {
      if (screen.form?.picked) app.sheetState.bills = (state?.incognito.coins ?? []).filter(coin => screen.form.picked.includes(coin.id));
    } else if (screen.form?.working) {
      app.sheetState.bills = state?.public.enterable ?? [];
    }
  }
  app.sparkPage = screen.page ?? 'wallet';
  Object.assign(app.model, screen.model);
  app.render();
  return true;
}
