// Shared screen chrome in the 760×814 design frame: the content column is
// 320 wide at left 220, the back button sits at 28×103.
import { h, icon } from '../components.js';
import { sats } from '../model.js';
import { intentRequest, progressText } from './adapter.js';
import { shortAddress } from './model.js';

const COLUMN = 220, WIDTH = 320;

/**
 * Sheet rhythm: content stacks up from the primary action at ACTION, GAP apart,
 * with a link or error at BELOW; art is centred between the header and that content.
 */
export const ACTION = 700, BELOW = 758, GAP = 32;
export const SECONDARY = ACTION - GAP - 44, FIELD_END = SECONDARY - GAP;
/** A result's amount with the 49px row under it. */
export const ROW = ACTION - GAP - 49, AMOUNT = ROW - 12 - 62;
export const headerEnd = subtitle => (subtitle ? 183 : 151);
export const centred = (above, below, height) => Math.round((above + below - height) / 2);

/** Absolutely places `node` in the frame. */
export function place(node, top, left = COLUMN, width = WIDTH) {
  node.style.setProperty('top', `${top}px`);
  node.style.setProperty('left', `${left}px`);
  if (width !== null) node.style.setProperty('width', `${width}px`);
  return node;
}

export function stage(label, ...children) {
  return h('main', { class: 'z-stage', 'aria-label': label }, children);
}

export function circleButton(label, symbol, { onClick, disabled, left = 28, top = 103 } = {}) {
  return place(h('button', { type: 'button', class: 'z-circle', 'aria-label': label, title: label, disabled, onClick },
    icon(symbol, 18)), top, left, null);
}

export const backButton = (app, onBack = () => app.back()) =>
  circleButton('Back', 'back', { onClick: onBack, disabled: app.model.busy });

export function title(text, subtitle) {
  return place(h('header', { class: 'z-title' }, h('h1', { text }), subtitle ? h('p', { text: subtitle }) : null), 111);
}

/** The wide action. Disabled actions take the quiet look the design gives them. */
export function primary(label, top, { disabled, onClick, quiet } = {}) {
  return place(h('button', { type: 'button', class: `z-action${quiet ? ' quiet' : ''}`, disabled, onClick, text: label }), top);
}

export function secondary(label, top, { disabled, onClick, left, width } = {}) {
  return place(h('button', { type: 'button', class: 'z-action quiet', disabled, onClick, text: label }), top, left, width);
}

export function textLink(label, top, onClick, { disabled, arrow = false } = {}) {
  return place(h('button', { type: 'button', class: 'z-link', disabled, onClick },
    h('span', { text: label }), arrow ? icon('forward', 14) : null), top);
}

export function note(text, top, extra = '') {
  return place(h('p', { class: `z-note ${extra}`, text }), top);
}

/** A labelled box, read-only (`value`) or editable (`input`). */
export function field(label, top, { value, input, height, tone = '' } = {}) {
  const box = h('div', { class: `z-field ${tone}` }, h('span', { class: 'z-field-label', text: label }),
    input ?? h('span', { class: 'z-field-value selectable', text: value }));
  if (height) box.style.setProperty('height', `${height}px`);
  return place(box, top);
}

/** The large display amount; pass `input` to make it editable. */
export function amount(valueSat, top, { label, input } = {}) {
  return place(h('div', { class: 'z-amount' },
    label ? h('span', { class: 'z-amount-label', text: label }) : null,
    h('div', { class: 'z-amount-line' },
      input ?? h('span', { class: 'z-amount-value', text: sats(valueSat) }),
      h('span', { class: 'z-amount-unit', text: 'sats' }))), top);
}

/** Digits while editing and grouped otherwise, so the caret stays where it was typed. */
export function amountInput(form, app, onEdit = () => {}) {
  const shown = () => (form.amount ? sats(form.amount) : '');
  // The sizer mirrors the text so the field is as wide as its proportional digits.
  const sizer = h('span', { class: 'z-amount-value z-amount-sizer' });
  const show = text => { input.value = text; sizer.dataset.value = text || '0'; };
  const input = h('input', {
    class: 'z-amount-input', key: 'spark-amount', placeholder: '0', size: 1,
    inputMode: 'numeric', autocomplete: 'off', spellcheck: false, 'aria-label': 'Amount in sats',
    onFocus: () => show(form.amount),
    onBlur: () => show(shown()),
    onInput: event => {
      form.amount = event.target.value.replace(/\D/g, '').slice(0, 16);
      onEdit(); app.render();
    },
  });
  sizer.append(input);
  show(shown());
  return sizer;
}

/** The pasted destination, shortened unless it is being edited. */
export function addressArea(form, app, { placeholder, onEdit = () => {}, disabled } = {}) {
  const shown = () => (form.address ? shortAddress(form.address.trim()) : '');
  const area = h('textarea', {
    class: `z-address${form.address ? ' filled' : ''}`, key: 'spark-address', value: shown(), placeholder, disabled, rows: 2,
    autocomplete: 'off', autocorrect: 'off', autocapitalize: 'off', spellcheck: false, 'aria-label': placeholder,
    onFocus: () => { area.value = form.address; },
    onBlur: () => { area.value = shown(); },
    onInput: event => { form.address = event.target.value.replace(/\s+/g, ''); onEdit(); app.render(); },
    onKeydown: event => { if (event.key === 'Enter') event.preventDefault(); },
  });
  return area;
}

/** A label and value split across the column with a hairline below. */
export function row(label, value, top) {
  return place(h('div', { class: 'z-row' }, h('span', { text: label }), h('strong', { text: value })), top);
}

/** Runs one intent; `after` runs only when the backend accepted it. Returns success. */
export async function run(app, intent, params, after) {
  const { action, args } = intentRequest(intent, params);
  await app.perform(action, args);
  if (app.model.error) return false;
  after?.();
  return true;
}

/** Runs `steps` as one visible operation: the screen stays in its working state between actions. */
export async function working(app, form, steps) {
  form.working = true;
  app.render();
  try { await steps(); } finally { form.working = false; app.render(); }
}

/** Reviews a payment, then sends it only if the review still matches the form. */
export function reviewAndSend(app, params, form, view) {
  return working(app, form, async () => {
    if (!await run(app, 'review', params)) return;
    if (!view().matches) { app.model.error = 'The wallet changed during review. Try again.'; return; }
    await run(app, 'send', params, () => { form.sent = true; app.clearReview(); });
  });
}

/** The running step's label, or `fallback` before the first one arrives. */
export const busyLabel = (model, fallback) => (model.stage ? progressText(model) : fallback);
