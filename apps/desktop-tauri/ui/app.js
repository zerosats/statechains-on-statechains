// Webview entry: bridges the backend to the views and owns screen navigation.
// Each flow ("sheet") is a full page over the 760×814 design frame.
import { initialModel, applyEvent, applyShellError, beginAction, endAction } from './model.js';
import { h } from './components.js';
import { connectBridge } from './bridge.js';
import { createWalletMotion } from './spark/motion.js';
import { sparkWalletView } from './spark/views.js';
import { sparkSheetState, sparkSendSheet, sparkSendBack, sparkDepositSheet, sparkReceiveSheet, sparkReceiveLoad } from './spark/sheets.js';
import { sparkEnterSheet, sparkExitSheet } from './spark/cash.js';
import { sparkReceivedSheet, sparkReceivedOpen } from './spark/result.js';
import { sparkState, newArrivals } from './spark/model.js';
import { applyPreviewScreen } from './spark/preview.js';

const SHEETS = {
  sparkSend: { render: sparkSendSheet, back: sparkSendBack },
  sparkEnter: { render: sparkEnterSheet },
  sparkExit: { render: sparkExitSheet },
  sparkDeposit: { render: sparkDepositSheet },
  sparkReceive: { render: sparkReceiveSheet, onOpen: sparkReceiveLoad },
  sparkReceived: { render: sparkReceivedSheet, onOpen: sparkReceivedOpen },
};

const root = document.getElementById('app');
const motion = createWalletMotion(root);
let bridge;

const app = {
  model: initialModel(),
  info: { preview: false, platform: '' },
  running: true,
  sheet: null,
  sheetState: null,
  side: 'public',
  sparkPage: 'wallet',
  // Received payments already accounted for (null until the first snapshot), and those still to show.
  seen: null,
  arrivals: [],

  async perform(action, args = {}) {
    if (app.model.busy || !app.running) return;
    beginAction(app.model, action);
    app.render();
    try { await bridge.perform(action, args); }
    finally { endAction(app.model); app.render(); }
  },

  openSheet(kind, fields = {}) {
    if (app.model.busy) return;
    app.sheet = kind;
    app.sparkPage = 'wallet';
    app.model.error = null;
    app.clearReview();
    app.sheetState = { ...sparkSheetState(kind), ...fields };
    app.render();
    SHEETS[kind].onOpen?.(app);
  },

  closeSheet() {
    if (app.model.busy) return;
    app.sheet = null;
    app.sheetState = null;
    app.model.error = null;
    app.clearReview();
    app.render();
  },

  /** One step back: within a flow first, then to the wallet. */
  back() {
    if (app.model.busy) return;
    if (app.sheet) {
      if (!SHEETS[app.sheet].back?.(app)) app.closeSheet();
    } else if (app.sparkPage !== 'wallet') {
      app.sparkPage = 'wallet';
      app.render();
    }
  },

  /** A form edit invalidates the payment review and its error. */
  clearReview() {
    app.model.preview = null;
    if (app.sheet === 'sparkSend') app.model.error = null;
  },

  /** Deposit and Go private/public land the user on the side that received the funds. */
  finishTransition(side) {
    app.side = side;
    app.closeSheet();
  },

  async qr(value) {
    const svg = await bridge.qrSvg(value);
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  },

  async copy(text) {
    try { await navigator.clipboard.writeText(text); }
    catch {
      // Older WebKitGTK builds lack the async clipboard API.
      const area = h('textarea', { value: text, class: 'offscreen' });
      document.body.append(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
  },

  render() {
    // Re-rendering replaces the tree; keep focus, caret and scroll positions.
    const focus = focusedControl();
    const scrollTop = root.scrollTop;
    const transition = motion.capture({ screen: screenKey() });

    document.body.classList.toggle('spark-incognito', app.side === 'incognito');
    const page = app.sheet ? SHEETS[app.sheet].render(app) : sparkWalletView(app);
    // A disabled fieldset disables every control on the page while an action runs.
    root.replaceChildren(h('fieldset', { class: 'z-frame', disabled: app.model.busy }, page));

    root.scrollTop = transition ? 0 : scrollTop;
    restoreFocus(focus);
    motion.play(transition);
    queueMicrotask(presentArrival);
  },
};

/** Queues payments that finished arriving; those already there at startup are not news. */
function noteArrivals() {
  const state = sparkState(app);
  if (!state) return;
  if (!app.seen) { app.seen = new Set(); newArrivals(state, app.seen); return; }
  app.arrivals.push(...newArrivals(state, app.seen));
}

/** Shows the oldest payment received on this side once the wallet is idle there, or waiting to receive. */
function presentArrival() {
  if ((app.sheet && app.sheet !== 'sparkReceive') || app.sparkPage !== 'wallet' || app.model.busy || sparkState(app)?.pending) return;
  const index = app.arrivals.findIndex(item => item.wallet === app.side);
  if (index < 0) return;
  const [arrival] = app.arrivals.splice(index, 1);
  app.openSheet('sparkReceived', { arrival });
}

/** Identifies the screen for motion: typing and polls keep it, steps change it. */
function screenKey() {
  const form = app.sheetState;
  const phase = app.sheet === 'sparkSend' ? [form?.step, form?.sent ? 'sent' : form?.working ? 'working' : ''] : [];
  return [app.side, app.sparkPage, app.sheet ?? 'home', ...phase, sparkState(app)?.pending ? 'checking' : ''].join('|');
}

const label = node => node.getAttribute('aria-label') ?? node.textContent;

/** Identifies the focused control by key, or by position and label when it has none. */
function focusedControl() {
  const node = document.activeElement;
  if (!node || node === document.body || !root.contains(node)) return null;
  const path = [];
  for (let child = node; child !== root; child = child.parentElement) path.unshift([...child.parentElement.children].indexOf(child));
  return { key: node.dataset.key, path, tag: node.tagName, label: label(node),
    caret: typeof node.selectionStart === 'number' ? [node.selectionStart, node.selectionEnd] : null };
}

function restoreFocus(focus) {
  if (!focus) return;
  let node;
  if (focus.key) node = root.querySelector(`[data-key="${CSS.escape(focus.key)}"]`);
  else {
    node = focus.path.reduce((parent, index) => parent?.children[index], root);
    // Only the same control in the same place: a changed layout drops focus instead of moving it.
    if (node?.tagName !== focus.tag || label(node) !== focus.label) node = null;
  }
  if (!node || node.disabled) return;
  node.focus({ preventScroll: true });
  if (focus.caret && typeof node.setSelectionRange === 'function') node.setSelectionRange(...focus.caret);
}

document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && (app.sheet || app.sparkPage !== 'wallet')) {
    event.preventDefault();
    app.back();
  }
});

async function start() {
  bridge = await connectBridge();
  app.info = await bridge.appInfo();
  document.body.classList.add('spark-shell', `platform-${app.info.platform}`);
  await bridge.onWallet(async payload => {
    if (payload.error) {
      applyShellError(app.model, payload.error);
      app.running = await bridge.isRunning();
    } else {
      // Most background polls change nothing; skip rebuilding the page for them.
      const before = JSON.stringify(app.model);
      applyEvent(app.model, payload.event, payload.isReply);
      if (JSON.stringify(app.model) === before) return;
      noteArrivals();
    }
    app.render();
  });
  app.render();
  await bridge.start();
  await app.perform('refresh');
  const screen = app.info.previewScreen;
  if (screen && !applyPreviewScreen(app, screen) && SHEETS[screen]) app.openSheet(screen);
}

start();
