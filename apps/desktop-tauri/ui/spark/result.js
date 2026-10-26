// Payment results. What was sent flies off the screen and a check takes its
// place; a received Incognito bill slots in beneath the others, then the
// wallet returns on its own.
import { h, icon } from '../components.js';
import { sats } from '../model.js';
import { fan, fanGroups } from './art.js';
import { sparkState } from './model.js';
import { stage, primary, place, ACTION } from './page.js';

const CHECK = 104, CHECK_TOP = 244, HEADING = 380, FIGURE = 436;
/** Below the risen fan on Cash received. */
const ARRIVAL_HEADING = 600, ARRIVAL_FIGURE = 648;
/** How long a received bill stays in view before the wallet returns. */
const ARRIVAL_MS = 2800;

/** Fades `node` in after `delay` ms, once what it replaces has moved. */
function reveal(node, delay) {
  node.classList.add('z-reveal');
  node.style.setProperty('--delay', `${delay}ms`);
  return node;
}

const heading = (text, top, delay) => reveal(place(h('header', { class: 'z-title' }, h('h1', { text })), top), delay);

const figure = (valueSat, top, delay) => reveal(place(h('div', { class: 'z-amount-line z-result-amount' },
  h('span', { class: 'z-amount-value', text: sats(valueSat) }), h('span', { class: 'z-amount-unit', text: 'sats' })), top), delay);

/** A finished payment; `leaving` is the bills or card it carried, flying off as the check arrives. */
export function resultScreen(app, label, amountSat, leaving = null) {
  return stage(label, leaving,
    place(h('span', { class: 'z-check', 'aria-hidden': 'true' }, icon('check', 48)), CHECK_TOP, 380 - CHECK / 2, null),
    heading(`${label}.`, HEADING, 520),
    figure(amountSat, FIGURE, 580),
    reveal(primary('Back to wallet', ACTION, { onClick: () => app.closeSheet() }), 640));
}

/** A payment that has just arrived: a check for Public, the new bill joining the fan for Incognito. */
export function sparkReceivedSheet(app) {
  const { arrival } = app.sheetState;
  if (arrival.wallet !== 'incognito') return resultScreen(app, 'Payment received', arrival.amountSat);
  const coins = sparkState(app)?.incognito.coins ?? [];
  const arrived = coins.find(coin => coin.id === arrival.coin) ?? { id: `arrival-${arrival.key}`, amountSat: arrival.amountSat };
  const groups = [...fanGroups(coins.filter(coin => coin !== arrived)), [arrived]];
  return stage('Cash received',
    fan(groups, 'arrival', (group, i) => (i === groups.length - 1 ? { motion: 'arriving' } : {})),
    heading('Cash received.', ARRIVAL_HEADING, 700),
    figure(arrival.amountSat, ARRIVAL_FIGURE, 760));
}

/** Cash received returns to the wallet by itself; a running action holds it until it ends. */
export function sparkReceivedOpen(app) {
  const form = app.sheetState;
  if (form.arrival.wallet !== 'incognito') return;
  const leave = () => {
    if (app.sheetState !== form) return;
    if (app.model.busy) setTimeout(leave, 500);
    else app.closeSheet();
  };
  setTimeout(leave, ARRIVAL_MS);
}
