// The only module that knows the blinded backend's wire shapes. Screens read
// `walletState` and send intents through `intentRequest`.

const SIDE_LABEL = { public: 'Public', incognito: 'Incognito', transition: 'Public ↔ Incognito' };
const coinOption = item => ({ id: item.id, amountSat: item.amountSat });

// Incoming entries that are still arriving; an interrupted claim is a reconciliation instead.
const arriving = incoming => (incoming ?? []).filter(item => item.state === 'pending' || item.state === 'claiming').length;

// Public moves to Incognito like an ATM withdrawal: the backend takes a bill
// value and swaps Public leaves for it with the SSP when no leaf is that bill.
const CASH = /^cash-(\d+)-\d+$/;
/** The most Public can withdraw as 10,000/5,000/2,000 bills, then the fewest bills. */
export function cashBills(totalSat) {
  let best = [];
  for (const fives of [0, 1]) {
    const rest = totalSat - fives * 5000;
    if (rest < 0) continue;
    const tens = Math.floor(rest / 10000), twos = Math.floor((rest - tens * 10000) / 2000);
    const bills = [...Array(tens).fill(10000), ...Array(fives).fill(5000), ...Array(twos).fill(2000)];
    const value = list => list.reduce((sum, bill) => sum + bill, 0);
    if (value(bills) > value(best) || (value(bills) === value(best) && bills.length < best.length)) best = bills;
  }
  // Numbered within each value, so picks left after a partial move still name bills of that value.
  return best.map((amountSat, i) => ({ id: `cash-${amountSat}-${i - best.indexOf(amountSat)}`, amountSat }));
}

/** The coin a private receipt created: its activity row is named after the coin. */
const receivedCoin = item => (item.kind === 'privateReceived' && item.id?.startsWith('private-received-')
  ? item.id.slice('private-received-'.length) : null);

/** The display shape of a snapshot; `null` until the first one. */
export function walletState(snapshot) {
  const b = snapshot?.blinded;
  if (!b) return null;
  const coins = b.incognito?.coins ?? [];
  const activity = [...(b.activity ?? [])].sort((x, y) => (y.at ?? 0) - (x.at ?? 0));
  return {
    profile: b.profile ?? 'Wallet',
    connected: snapshot.connected !== false,
    pending: b.status === 'blocked' || b.operation?.state === 'interrupted',
    ingressMinSat: b.denominationSat ?? 2000,
    public: {
      totalSat: b.public?.totalSat ?? 0,
      address: b.public?.address ?? '',
      sendable: (b.public?.leaves ?? []).filter(leaf => leaf.available),
      enterable: cashBills((b.public?.leaves ?? []).filter(leaf => leaf.available).reduce((sum, leaf) => sum + leaf.amountSat, 0)),
      incoming: arriving(b.public?.incoming),
    },
    incognito: {
      totalSat: b.incognito?.totalSat ?? 0,
      address: b.incognito?.address ?? '',
      coins: coins.map(coin => ({ ...coinOption(coin), canSend: Boolean(coin.canSend) })),
      sendable: coins.filter(coin => coin.canSend),
      exitable: coins.filter(coin => coin.canGoPublic).map(coinOption),
      incoming: arriving(b.incognito?.incoming),
    },
    activity: activity.map(item => ({ key: item.id, label: item.label, amountSat: item.amountSat, side: SIDE_LABEL[item.side] ?? 'Public',
      wallet: item.side, kind: item.kind, state: item.state, at: item.at ?? 0, coin: receivedCoin(item) })),
  };
}

/** Maps a UI intent to the backend's `{ action, args }`. */
export function intentRequest(intent, { side, address, amountSat, coins, id } = {}) {
  switch (intent) {
    case 'deposit': return { action: 'publicDeposit', args: { amountSat } };
    case 'goPrivate': {
      const cash = CASH.exec(id ?? '');
      return { action: 'goPrivate', args: cash ? { amountSat: Number(cash[1]) } : { leaf: id } };
    }
    case 'goPublic': return { action: 'goPublic', args: { coin: id } };
    case 'review': return { action: 'preview', args: side === 'incognito' ? { side, address, coins } : { side, address, amountSat } };
    case 'send': return side === 'incognito' ? { action: 'privateSend', args: { address, coins } }
      : { action: 'publicSend', args: { address, amountSat } };
    default: throw new Error(`Unknown intent ${intent}`);
  }
}

/** The reviewed payment shown on Confirm payment, or `null`. */
export function reviewState(model) {
  const preview = model.preview;
  if (!preview) return null;
  return { side: preview.side, amountSat: preview.amountSat, changeSat: preview.changeSat, feeSat: preview.feeSat, inputs: preview.inputs ?? [] };
}

/** The current step's text for long operations. */
export function progressText(model) {
  const label = model.stage?.label;
  if (label) return label.endsWith('…') ? label : `${label}…`;
  return model.progress || 'Working…';
}
