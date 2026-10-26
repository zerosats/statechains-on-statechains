// Incognito cash screens (Paper "zarkxspark", New design I01–I06, I09, P10, E02).
// Bills keep their `data-shared` keys from screen to screen so they stay in view.
import { h, icon } from '../components.js';
import { sats } from '../model.js';
import { bills, fan, fanGroups, fanSlots, markTop, stackSlots, stackTop, badge, blankBills, PICK_MARK_LEFT } from './art.js';
import { sparkState, sendView, togglePick, actionsBlocked, shortAddress, MAX_SEND_BILLS } from './model.js';
import {
  stage, backButton, title, primary, secondary, note, field, amount, addressArea, row, place, run, working,
  reviewAndSend, busyLabel, ACTION, BELOW, GAP, SECONDARY, FIELD_END, ROW, AMOUNT, headerEnd, centred,
} from './page.js';
import { resultScreen } from './result.js';

const NOTE_TOP = ACTION - GAP - 21, ADDRESS_TOP = FIELD_END - 103;

const plural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
const total = coins => coins.reduce((sum, coin) => sum + coin.amountSat, 0);

/** Opens the bill picker, optionally with the bill the user tapped already picked. */
export function openCashSend(app, coinId) {
  app.openSheet('sparkSend', coinId ? { picked: [coinId] } : {});
}

/**
 * A fan of piles that pick bills, with a mark beside each pile. Tapping a pile
 * picks its next bill while the limit allows, then puts the whole pile back.
 */
function pickFan(app, coins, form, limit) {
  const groups = fanGroups(coins), slots = fanSlots(groups.length, 'pick'), picked = new Set(form.picked);
  const full = picked.size >= limit;
  const chosen = group => group.filter(coin => picked.has(coin.id)).length;
  const toggle = group => () => {
    const next = group.find(coin => !picked.has(coin.id));
    if (next && !full) togglePick(form, next.id, limit);
    else form.picked = form.picked.filter(id => !group.some(coin => coin.id === id));
    app.clearReview();
    app.render();
  };
  const marks = groups.map((group, i) => {
    const count = chosen(group);
    const mark = h('button', { type: 'button', class: `z-mark${count ? ' on' : ''}`, tabIndex: -1, 'aria-hidden': 'true',
      disabled: app.model.busy || (!count && full), onClick: toggle(group) },
    count > 1 ? h('span', { text: String(count) }) : count ? icon('check', 15) : null);
    return place(mark, markTop(slots, i), PICK_MARK_LEFT, null);
  });
  return [
    fan(groups, 'pick', group => ({
      onClick: toggle(group), pressed: chosen(group) > 0, disabled: app.model.busy || (!chosen(group) && full),
      label: `${sats(group[0].amountSat)} sats note${group.length > 1 ? `, ${chosen(group)} of ${group.length} picked` : ''}`,
    })),
    marks,
  ];
}

function summary(coins) {
  return place(h('div', { class: 'z-summary' },
    h('span', { text: `${plural(coins.length, 'note')} selected` }),
    h('strong', { text: `${sats(total(coins))} sats` })), ACTION - GAP - 26);
}

const ADDRESS_LABEL = {
  empty: 'Incognito address',
  ready: 'Incognito address · ready',
  other: 'Public address · not supported',
  own: 'Your own address · use another wallet',
  invalid: 'Not an Incognito address',
};

export function incognitoSendScreen(app) {
  const form = app.sheetState, state = sparkState(app);
  form.step ??= 'pick';
  const sendable = state?.incognito.sendable ?? [];
  if (form.step === 'pick') {
    const chosen = sendable.filter(coin => form.picked.includes(coin.id));
    return stage('Choose your cash', backButton(app),
      title('Choose your cash.', 'Select one or two notes to send.'),
      sendable.length ? pickFan(app, sendable, form, MAX_SEND_BILLS) : note('No notes are ready to send.', 300, 'center'),
      summary(chosen),
      primary(chosen.length ? `Continue with ${plural(chosen.length, 'note')}` : 'Choose a note', ACTION, {
        disabled: !chosen.length, onClick: () => { form.bills = chosen; form.step = 'address'; app.render(); },
      }));
  }
  const view = sendView(app, form), coins = form.bills, sum = total(coins);
  const to = row('To', shortAddress(view.address, 16, 4), ROW);
  const top = stackTop(headerEnd(), AMOUNT, 50), carried = options => bills(coins, stackSlots(coins.length, top, 50), options);
  if (form.sent) return resultScreen(app, 'Cash sent', sum, carried(() => ({ motion: 'leaving' })));
  if (form.working) {
    return stage('Sending your cash', backButton(app, () => app.closeSheet()), title('Sending your cash.'),
      carried(), badge('pending', 536, top + 165), amount(sum, AMOUNT), to,
      primary(busyLabel(app.model, 'Sending…'), ACTION, { disabled: true }));
  }
  const wrong = view.target === 'other', ready = view.target === 'ready';
  const tone = ready ? 'ready' : ['empty'].includes(view.target) ? '' : 'bad';
  const params = { side: 'incognito', address: view.address, coins: view.coins };
  const subtitle = wrong ? 'These notes need an Incognito address.' : undefined;
  return stage(wrong ? 'Wrong address' : 'Send your cash', backButton(app),
    title(wrong ? 'Wrong address.' : 'Send your cash.', subtitle),
    bills(coins, stackSlots(coins.length, stackTop(headerEnd(subtitle), ADDRESS_TOP))),
    field(ADDRESS_LABEL[view.target], ADDRESS_TOP, {
      height: ready ? 173 : 103, tone,
      input: addressArea(form, app, { placeholder: 'Paste an address', onEdit: () => { app.model.error = null; app.clearReview(); } }),
    }),
    app.model.error ? note(app.model.error, (ready ? ADDRESS_TOP + 173 : FIELD_END) + 6, 'danger selectable') : null,
    ready ? null : secondary('Scan QR Code', SECONDARY, { disabled: true }),
    primary(`Send ${sats(sum)} sats`, ACTION, {
      disabled: !view.canSend || view.coins.length !== coins.length,
      onClick: () => reviewAndSend(app, params, form, () => sendView(app, form)),
    }));
}

/**
 * Moves each coin in turn; one failure stops the rest and leaves its error on
 * screen, with the bills that did not move still picked.
 */
function moveEach(app, form, intent, ids, target) {
  form.total = ids.length;
  return working(app, form, async () => {
    for (const [i, id] of ids.entries()) {
      form.moving = i + 1;
      if (!await run(app, intent, { id })) { form.picked = ids.slice(i); return; }
    }
    app.finishTransition(target);
  });
}

const movingLabel = (app, form) => `Note ${form.moving} of ${form.total} · ${busyLabel(app.model, 'Moving…')}`;

function nothingToMove(app, heading, text, action) {
  // The tilted blanks reach 19px above the front one's top and span 214px in all.
  return stage(heading, backButton(app), title(heading),
    blankBills(action.onClick, action.label, action.disabled, centred(headerEnd(), NOTE_TOP, 214) + 19),
    note(text, NOTE_TOP, 'center'),
    primary(action.label, ACTION, action));
}

export function sparkEnterSheet(app) {
  const form = app.sheetState, state = sparkState(app), notes = state?.public.enterable ?? [];
  const minimum = sats(state?.ingressMinSat ?? 2000), held = state?.public.totalSat ?? 0;
  if (!notes.length && !form.working) {
    return nothingToMove(app, 'No cash yet.', held
      ? `Public holds ${sats(held)} sats. Notes start at ${minimum} sats.`
      : `Add at least ${minimum} sats to create notes.`,
      { label: 'Add test funds', disabled: actionsBlocked(app), onClick: () => app.openSheet('sparkDeposit') });
  }
  // The notes Public's balance can make; each picked one is withdrawn by value.
  const shown = form.working ? form.bills : notes;
  const chosen = shown.filter(bill => form.picked.includes(bill.id));
  // Notes come in 10,000, 5,000 and 2,000; whatever is not picked or does not make a note stays in Public.
  const left = held - total(chosen);
  const below = app.model.error ? note(app.model.error, BELOW, 'danger selectable')
    : left > 0 ? note(`${sats(left)} sats stay in Public`, BELOW, 'center') : null;
  return stage('Make it cash', backButton(app),
    title('Make it cash.', 'Choose notes for your Incognito balance.'),
    pickFan(app, shown, form, Infinity),
    summary(chosen),
    primary(form.working ? movingLabel(app, form) : chosen.length ? `Move ${sats(total(chosen))} sats` : 'Choose notes', ACTION, {
      disabled: form.working || actionsBlocked(app) || !chosen.length,
      onClick: () => { form.bills = shown; moveEach(app, form, 'goPrivate', chosen.map(bill => bill.id), 'incognito'); },
    }),
    form.working ? null : below);
}

export function sparkExitSheet(app) {
  const form = app.sheetState, coins = sparkState(app)?.incognito.exitable ?? [];
  if (!coins.length && !form.working) {
    return nothingToMove(app, 'Nothing to move.', 'No notes can move to Public right now.',
      { label: 'Back to wallet', onClick: () => app.closeSheet() });
  }
  const shown = form.working ? form.bills : coins;
  const chosen = shown.filter(coin => form.picked.includes(coin.id));
  return stage('Move to Public', backButton(app),
    title('Move to Public.', 'Choose notes for your Public balance.'),
    pickFan(app, shown, form, Infinity),
    summary(chosen),
    primary(form.working ? movingLabel(app, form) : chosen.length ? `Move ${sats(total(chosen))} sats` : 'Choose notes', ACTION, {
      disabled: form.working || actionsBlocked(app) || !chosen.length,
      onClick: () => { form.bills = shown; moveEach(app, form, 'goPublic', chosen.map(coin => coin.id), 'public'); },
    }),
    app.model.error && !form.working ? note(app.model.error, BELOW, 'danger selectable') : null);
}
