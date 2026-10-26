// Bills and route cards (Paper "zarkxspark", New design). Positions are in the
// 760×814 design frame. Each piece carries a `data-shared` key so motion.js can
// carry the same bill or card across screens.
import { h, icon } from '../components.js';
import { sats } from '../model.js';

/** Each denomination's note: black or white, which sets the colour of its edge. */
const BILL_INK = { 10000: 'dark', 5000: 'light', 2000: 'dark' };

/** Fans: alternating lefts, the highest and lowest bill tops, and the widest gap between bills. */
const FANS = {
  home: { lefts: [232, 250, 236, 254], first: 272, last: 427, gap: 66 },
  // The home fan risen to make room below for a bill that has just arrived.
  arrival: { lefts: [232, 250, 236, 254], first: 232, last: 387, gap: 66 },
  pick: { lefts: [201, 237, 207, 241], first: 244, last: 427, gap: 74, centre: true },
};
/** Selection marks sit in this column beside the pick fan. */
export const PICK_MARK_LEFT = 535;
const RAD = Math.PI / 180;

/** Tilts only grow down the fan, so each bill's right edge stays below the one above it. */
const tilt = (i, count) => count === 1 ? -2 : count === 2 ? [-4.5, 2][i] : -4.5 + (9 * i) / (count - 1);

/**
 * [left, top, rotation°] per bill, topmost first: bills climb evenly above the lowest,
 * which stays put on the home fan and keeps the fan centred in its band on the others.
 * Each bill lies over the one above it, so every bill's denomination stays in view.
 */
export function fanSlots(count, kind) {
  const { lefts, first, last, gap, centre } = FANS[kind];
  const step = Math.min(gap, (last - first) / Math.max(count - 1, 1));
  const lowest = centre ? (first + last + step * (count - 1)) / 2 : count === 1 ? last - step / 2 : last;
  return Array.from({ length: count }, (_, i) => [
    count === 1 ? (lefts[0] + lefts[1]) / 2 : lefts[i % lefts.length],
    Math.round(lowest - step * (count - 1 - i)),
    tilt(i, count),
  ]);
}

const upperRight = ([, top, rotation]) => top + 277 * Math.sin(rotation * RAD);
const lowerRight = ([, top, rotation]) => upperRight([0, top, rotation]) + 156 * Math.cos(rotation * RAD);

/** Top of a 24px mark centred on the part of a fan bill's right edge left in view. */
export function markTop(slots, i) {
  const start = upperRight(slots[i]), end = i < slots.length - 1 ? upperRight(slots[i + 1]) : start + 26;
  return Math.round((start + end) / 2 - 12);
}

/** The tilted pair a send carries; a single bill sits between the two. */
export function stackSlots(count, top, gap = 43) {
  if (count === 1) return [[242, top + gap / 2, -2]];
  return [[233, top, -4.5], [251, top + gap, 2]].slice(0, count);
}

/** The `stackSlots` top that centres the tilted pair, corners included, between `above` and `below`. */
export const stackTop = (above, below, gap = 43) =>
  Math.round((above + below + 277 * Math.sin(4.5 * RAD) - lowerRight([0, gap, 2])) / 2);

/** Bills as fan piles: one each up to the design's four, else one pile per denomination, largest first. */
export function fanGroups(coins) {
  if (coins.length <= 4) return coins.map(coin => [coin]);
  const piles = new Map();
  for (const coin of coins) piles.set(coin.amountSat, [...(piles.get(coin.amountSat) ?? []), coin]);
  return [...piles.values()].sort((a, b) => b[0].amountSat - a[0].amountSat);
}

/**
 * A fan of piles. Each pile's top bill takes the slot and shows the pile's size;
 * the rest sit unseen beneath it so motion.js can still carry each one.
 */
export function fan(groups, kind, options = () => ({})) {
  const slots = fanSlots(groups.length, kind);
  let z = 0;
  return groups.map((group, i) => {
    const front = { ...options(group, i), count: group.length }, top = (z += group.length);
    return group.map((coin, j) => bill(coin, slots[i], top - j, j ? { under: true } : front));
  });
}

/**
 * One bill. `onClick` makes it a button; `muted` dims a bill that cannot move; `count` marks a pile;
 * `motion` ('leaving' or 'arriving') sends it off the screen or slides it into place.
 */
export function bill(coin, [left, top, rotation], z, { onClick, label, pressed, muted, disabled, under, count, motion } = {}) {
  const ink = BILL_INK[coin.amountSat];
  const face = ink
    ? h('img', { src: `spark/media/bill-${coin.amountSat}.jpg`, alt: '', draggable: false })
    : h('span', { class: 'z-bill-plain' }, h('strong', { text: sats(coin.amountSat) }), h('span', { text: 'satoshis' }));
  return h(onClick ? 'button' : 'div', {
    class: `z-bill${ink ? ` ${ink}` : ''}${muted ? ' muted' : ''}${under ? ' under' : ''}${motion ? ` ${motion}` : ''}`, type: onClick ? 'button' : undefined, onClick, disabled,
    'aria-hidden': under ? 'true' : undefined,
    'aria-label': label ?? `${sats(coin.amountSat)} sats note`, 'aria-pressed': pressed === undefined ? undefined : String(pressed),
    'data-shared': `bill:${coin.id}`,
    style: { left: `${left}px`, top: `${top}px`, rotate: `${rotation}deg`, '--z': String(z) },
  }, face, count > 1 ? h('span', { class: 'z-count', 'aria-hidden': 'true', text: `×${count}` }) : null);
}

/** A whole set of bills, topmost first, each lying over the one above. */
export function bills(coins, slots, options = () => ({})) {
  return coins.map((coin, i) => bill(coin, slots[i], i + 1, options(coin, i)));
}

/** A payment route card, its name part of the art; `rect` is [left, top, width, height]. */
export function routeCard(route, [left, top, width, height], extra = '') {
  return h('div', {
    class: `z-card z-card-${route} ${extra}`, 'aria-hidden': 'true', 'data-shared': `card:${route}`,
    style: { left: `${left}px`, top: `${top}px`, width: `${width}px`, height: `${height}px` },
  });
}

/** The pending mark beside a card or bill stack. */
export function badge(kind, left, top) {
  return h('span', { class: `z-badge ${kind}`, style: { left: `${left}px`, top: `${top}px` } },
    icon('pending', 22));
}

/** Blank bills with an add mark, for wallets without any yet; `top` is the front bill's. */
export function blankBills(onAdd, label, disabled, top = 260) {
  return [
    h('div', { class: 'z-blank back', 'aria-hidden': 'true', style: { top: `${top + 20}px` } }),
    h('div', { class: 'z-blank front', style: { top: `${top}px` } },
      h('button', { type: 'button', class: 'z-add', 'aria-label': label, title: label, disabled, onClick: onAdd }, icon('plus', 20))),
  ];
}
