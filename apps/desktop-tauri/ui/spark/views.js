// Spark home, status and activity pages (Paper "zarkxspark", New design 02,
// Incognito · Final, E01, E03, P11, P12, I10).
import { h, icon } from '../components.js';
import { sats } from '../model.js';
import { routeCard, fan, fanGroups, blankBills } from './art.js';
import { actionsBlocked, homeView, sparkState } from './model.js';
import { stage, circleButton, title, primary, note, amount, textLink, place, ACTION, BELOW, GAP, headerEnd, centred } from './page.js';
import { openCashSend } from './cash.js';

/** The paused note keeps room for two lines above the action. */
const PAUSED = ACTION - GAP - 42;

export function sparkWalletView(app) {
  if (app.sparkPage === 'activity') return activityPage(app);
  const view = homeView(app);
  return view.reconciliation ? checkingPage(app, view) : homePage(app, view);
}

function sideToggle(app, view) {
  const pick = side => () => { app.side = side; app.clearReview(); app.model.error = null; app.render(); };
  return [['public', 'Public', 268], ['incognito', 'Incognito', 384]].map(([side, label, left]) =>
    place(h('button', {
      type: 'button', class: `z-toggle${view.side === side ? ' on' : ''}`, text: label, disabled: app.model.busy,
      'aria-pressed': String(view.side === side), onClick: view.side === side ? undefined : pick(side),
    }), 100, left, 108));
}

function balance(valueSat) {
  return place(h('div', { class: 'z-balance', 'aria-label': `${sats(valueSat)} sats` },
    h('span', { class: 'z-balance-value', text: sats(valueSat) }), h('span', { class: 'z-balance-unit', text: 'sats' })), 151);
}

const ROUTE_STACK = [['bitcoin', [249, 315, 261, 165]], ['lightning', [245, 370, 269, 170]], ['spark', [241, 425, 277, 175], 'front']];

function publicArt(view) {
  return [
    view.funded
      ? place(h('div', { class: 'z-handle', 'aria-disabled': 'true', title: 'Not available yet' },
        icon('search', 16), h('span', { text: 'Pay a name or @handle' })), 246, 264, 232)
      : place(h('p', { class: 'z-caption', text: 'Receive your first sats.' }), 259, 242, 277),
    ROUTE_STACK.map(([route, rect, extra]) => routeCard(route, rect, extra)),
  ];
}

function incognitoArt(app, view) {
  if (!view.bills.length) {
    const enter = sparkState(app)?.public.enterable.length;
    return blankBills(() => app.openSheet(enter ? 'sparkEnter' : 'sparkDeposit'),
      enter ? 'Move to Incognito' : 'Add test funds', actionsBlocked(app));
  }
  return fan(fanGroups(view.bills), 'home', group => {
    const coin = group.find(item => item.canSend), amount = sats(group[0].amountSat);
    return {
      onClick: coin && !view.sendDisabled ? () => openCashSend(app, coin.id) : undefined,
      muted: !coin,
      label: coin ? `Send ${amount} sats note` : `${amount} sats note · not ready to send`,
    };
  });
}

function homePage(app, view) {
  const incognito = view.side === 'incognito';
  // The design gives the accent to whichever main action can start now.
  const sendLeads = !view.sendDisabled;
  const status = view.error ? note(view.error, 726, 'danger center selectable')
    : view.notice ? note(view.notice, 726, 'danger center')
      : view.status ? note(view.status, 730, 'center') : null;
  return stage(incognito ? 'Incognito wallet' : 'Public wallet',
    circleButton('Activity', 'activity', { disabled: app.model.busy, onClick: () => { app.sparkPage = 'activity'; app.render(); } }),
    sideToggle(app, view),
    balance(view.balanceSat),
    incognito ? incognitoArt(app, view) : publicArt(view),
    homeAction('Send', 623, sendLeads, view.sendDisabled, () => app.openSheet('sparkSend')),
    homeAction('Receive', 676, !sendLeads, view.receiveDisabled, () => app.openSheet('sparkReceive')),
    status,
    place(h('button', { type: 'button', class: 'z-link', disabled: view.link.disabled, onClick: () => app.openSheet(view.link.sheet) },
      h('span', { text: view.link.label }), icon('forward', 14)), 760, 242, 277),
    place(h('footer', { class: 'z-footer', text: view.footer }), 792, 242, 277));
}

function homeAction(label, top, lead, disabled, onClick) {
  return place(h('button', { type: 'button', class: `z-action home${lead && !disabled ? '' : ' quiet'}`, text: label, disabled, onClick }),
    top, 242, 277);
}

function checkingPage(app, view) {
  return stage('Checking status',
    circleButton('Activity', 'activity', { disabled: app.model.busy, onClick: () => { app.sparkPage = 'activity'; app.render(); } }),
    title('Checking status.'),
    place(h('span', { class: 'z-badge large pending' }, icon('pending', 22)), centred(headerEnd(), PAUSED - GAP - 90, 48), 356, null),
    amount(view.balanceSat, PAUSED - GAP - 90, { label: 'Last confirmed balance' }),
    note(view.error ?? 'Payments are paused while we check this transfer.', PAUSED, view.error ? 'danger selectable' : ''),
    primary(app.model.busy ? 'Checking…' : 'Check status', ACTION, {
      disabled: app.model.busy || !app.running, onClick: () => app.perform('refresh'),
    }));
}

const LABELS = {
  deposit: () => ['Funds added', 'Public', 1],
  publicSent: () => ['Payment sent', 'Spark', -1],
  publicReceived: () => ['Payment received', 'Spark', 1],
  goPrivate: side => ['Moved to Incognito', side === 'incognito' ? 'From Public' : 'Balance transfer', side === 'incognito' ? 1 : -1],
  goPublic: side => ['Moved to Public', side === 'public' ? 'From Incognito' : 'Balance transfer', side === 'public' ? 1 : -1],
  privateSent: () => ['Cash sent', '1 note', -1],
  privateReceived: () => ['Cash received', '1 note', 1],
};

const STATES = { pending: 'Pending', running: 'Pending', interrupted: 'Checking', failed: 'Failed' };
const time = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
const date = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });

/** Today's entries show the time, yesterday's say so, older ones show the date. */
export function activityTime(at, now = new Date()) {
  if (!at) return '';
  const when = new Date(at), day = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  if (when.getTime() >= day) return time.format(when);
  if (when.getTime() >= day - 86_400_000) return 'Yesterday';
  return date.format(when);
}

/** Each side lists its own entries and every transfer between the two. */
export function activityRows(state, side) {
  return (state?.activity ?? [])
    .filter(item => item.wallet === side || item.wallet === 'transition')
    .map(item => {
      const [label, detail, sign] = (LABELS[item.kind] ?? (() => [item.label, item.side, 1]))(side);
      const when = item.state && item.state !== 'complete' ? STATES[item.state] ?? item.state : activityTime(item.at);
      return { key: item.key, label, detail, sign, amountSat: item.amountSat, when, kind: item.kind };
    });
}

function activityRow(item, top) {
  return place(h('li', { class: 'z-activity-row' },
    h('span', { class: 'z-activity-icon' }, icon(item.sign < 0 ? 'sent' : 'received', 16)),
    h('span', { class: 'z-activity-label' }, h('strong', { text: item.label }),
      h('span', { text: [item.detail, item.when].filter(Boolean).join(' · ') })),
    h('span', { class: 'z-activity-amount' }, h('strong', { text: `${item.sign < 0 ? '−' : '+'}${sats(item.amountSat)}` }),
      h('span', { text: 'sats' }))), top);
}

function activityPage(app) {
  const incognito = app.side === 'incognito', rows = activityRows(sparkState(app), app.side);
  const back = circleButton('Back to wallet', 'back', { disabled: app.model.busy, onClick: () => app.back() });
  const refresh = () => app.perform('refresh');
  if (!rows.length) {
    return stage('Activity', back,
      place(h('p', { class: 'z-empty', text: 'Nothing here yet.' }), 370),
      textLink('Refresh activity', BELOW, refresh, { disabled: app.model.busy || !app.running }));
  }
  const first = incognito ? 312 : 228;
  const list = h('ol', { class: 'z-activity', 'aria-label': 'Wallet activity' },
    rows.map((item, i) => activityRow(item, first + i * 82)));
  if (incognito) {
    return stage('Incognito history', back,
      place(h('p', { class: 'z-eyebrow' }, h('span', { text: 'INCOGNITO' }), h('span', { text: 'HISTORY' })), 111),
      place(h('header', { class: 'z-title' }, h('h1', { text: 'Activity.' }), h('p', { text: 'Your activity on this device.' })), 165),
      place(h('p', { class: 'z-section', text: 'Recent' }), 276),
      list,
      textLink('Refresh activity', Math.max(BELOW, first + rows.length * 82 + 16), refresh, { disabled: app.model.busy || !app.running }));
  }
  return stage('Activity', back, title('Activity.'),
    circleButton('Refresh activity', 'refresh', { disabled: app.model.busy || !app.running, onClick: refresh, left: 500 }),
    list);
}
