// Mock wallet data in the blinded snapshot shape.
// Funded balances follow the Paper design, made of the backend's 10,000/5,000/2,000 bills.

const publicLeaf = (id, amountSat) => ({ id, amountSat, available: true });
const coin = (id, amountSat, origin = 'received') => ({ id, amountSat, state: 'available', origin, canSend: true, canGoPublic: true });

/** The other local profile on the mock network; the only valid recipient. */
export const RECIPIENT = { profile: 'two', public: `spark-regtest:03${'3'.repeat(64)}`, incognito: `zark-regtest:${'3'.repeat(64)}` };

function base() {
  return {
    network: 'mock', profile: 'one', status: 'ready', blocked: null, operation: null, denominationSat: 2000,
    public: { address: `spark-regtest:02${'1'.repeat(64)}`, totalSat: 0, leaves: [], incoming: [] },
    incognito: { address: `zark-regtest:${'2'.repeat(64)}`, totalSat: 0, coins: [], incoming: [] },
    activity: [],
  };
}

/** Incognito bills of the funded wallet, topmost first. */
export const COINS = ['00112233445566778899aabbcc7d8e9f', 'ffeeddccbbaa99887766554433aa11bb', '0a1b2c3d4e5f60718293a4b5c6d7e8f9', '9f8e7d6c5b4a39281706f5e4d3c2b1a0'];

function funded() {
  const wallet = base();
  const leaves = [10000, 10000, 10000, 10000, 10000, 10000, 2000, 2000];
  wallet.public.leaves = leaves.map((amountSat, i) => publicLeaf(`0f6c1d2e-3a4b-4c5d-8e9f-a0b1c24a1b${i}c`, amountSat));
  wallet.incognito.coins = [10000, 5000, 2000, 2000].map((amountSat, i) => coin(COINS[i], amountSat, i % 2 ? 'public' : 'received'));
  const ago = minutes => Date.now() - minutes * 60_000, row = (id, side, kind, label, amountSat, at) =>
    ({ id, side, kind, label, amountSat, state: 'complete', at, counterparty: kind.startsWith('private') ? 'two' : null });
  wallet.activity = [
    row('a1', 'public', 'deposit', 'Deposited to Public', 70000, ago(1700)),
    row('a2', 'transition', 'goPrivate', 'Moved to Incognito', 10000, ago(1500)),
    row('a3', 'transition', 'goPrivate', 'Moved to Incognito', 2000, ago(1490)),
    row('a4', 'public', 'publicReceived', 'Received payment', 8000, ago(90)),
    row('a5', 'incognito', 'privateReceived', 'Received payment', 5000, ago(60)),
    row('a6', 'public', 'publicSent', 'Sent payment', 2000, ago(20)),
    row('a7', 'incognito', 'privateReceived', 'Received payment', 2000, ago(5)),
  ];
  return wallet;
}

export function mockWallet(scenario) {
  const wallet = scenario === 'empty' ? base() : funded();
  if (scenario === 'pending') {
    wallet.status = 'blocked';
    wallet.blocked = { reason: 'Moving a coin to Public', operation: 'goPublic', profile: 'one' };
  }
  if (scenario === 'disconnected') wallet.public = { address: null, totalSat: 0, leaves: [], incoming: [] };
  if (scenario === 'incoming') wallet.incognito.incoming = [{ id: 'f'.repeat(32), amountSat: 64000, state: 'pending' }];
  return totals(wallet);
}

export function totals(wallet) {
  wallet.public.totalSat = wallet.public.leaves.reduce((sum, leaf) => sum + leaf.amountSat, 0);
  wallet.incognito.totalSat = wallet.incognito.coins.reduce((sum, item) => sum + item.amountSat, 0);
  return wallet;
}

/** Steps and labels per operation, as the blinded worker emits them. */
export const STEPS = {
  publicDeposit: [['fund', 'Funding from the regtest faucet'], ['observe', 'Confirming the deposit']],
  goPrivate: [['preflight', 'Checking the Spark leaf'], ['swap', 'Getting cash from the SSP'], ['identity', 'Creating a joint identity'],
    ['transfer', 'Moving the leaf'], ['claim', 'Claiming with the joint key'], ['prove_receive', 'Proving receive'],
    ['prove_origin', 'Proving the new coin'], ['finalize', 'Finalizing']],
  publicSend: [['swap', 'Making change with the SSP'], ['transfer', 'Sending on Spark'], ['deliver', 'Notifying the recipient']],
  privateSend: [['reserve', 'Reserving the coin'], ['prove_sender', 'Proving ownership'], ['authorize', 'Authorizing the handover'], ['deliver', 'Delivering privately']],
  goPublic: [['self_handover', 'Preparing the coin to leave'], ['head', 'Checking the coin'], ['release', 'Releasing the signer share'],
    ['chain_gate', 'Checking the chain'], ['send', 'Sending on Spark'], ['claim', 'Claiming into Public'], ['finalize', 'Finalizing']],
};
