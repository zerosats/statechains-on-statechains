# Future work: Spark SSP (OpenSSP)

This demo talks to an unmodified OpenSSP for **Public** leaf swaps only.
Private Incognito payments never go through an SSP: they are Zark handovers
that leave Spark's transfer history unchanged. The next product step is a
Zark-aware SSP that can reshape **private** coins the same way OpenSSP
reshapes ordinary Spark leaves.

Related code today: [PUBLIC-SSP-SWAPS.md](../integrations/spark/PUBLIC-SSP-SWAPS.md),
the Public swap journal in
[`desktop/public_swap.rs`](../integrations/spark/cosigner/src/private_transfer/real_fixture/live_receive/desktop/public_swap.rs),
and the ATM path in
[`desktop/atm.rs`](../integrations/spark/cosigner/src/private_transfer/real_fixture/live_receive/desktop/atm.rs).
The stack is pinned in [`sources.json`](../integrations/spark/sources.json)
(`open-ssp` `8952579`, Spark `5e0c879`).

## What the demo already does with OpenSSP

Public is an ordinary Spark wallet. When it cannot pay an exact set of up to
four leaves, it runs Spark's Swap V3: it sends covering leaves to the SSP
and gets back `[amount] + change`. That same swap is the ATM step: Public
asks the SSP for a 10,000 / 5,000 / 2,000-sat **root** leaf, then Go private
enters that leaf as an Incognito note.

`scripts/spark-dev.sh up` tops the SSP with a small ladder of those root
notes. Split children the SSP might return never pass Incognito's entry
shape check, so a depleted SSP fails with `no_cash_leaf` and the value
stays on Public.

OpenSSP, the operators and the Spark SDK stay unmodified. That is the
demo's main public claim. Keep it that way unless a change is unavoidable
and listed.

## Why a native SSP swap cannot serve Incognito

A native swap is a visible Spark transfer from the coin's identity key.
Its targets disclose the payment amount. The leaves it returns are no
longer separate Zark coins. The joint identity / USER key would also need
adaptor and transfer-package signatures the blind co-signer does not
produce.

So a private swap has to be a Zark handover: the wallet and the SSP
exchange whole coins through the same sender-proof / receiver-proof path
Alice and Bob already use. Spark operators see nothing. The SSP sees the
coins and amounts it gave and received, and the wallet's claim key. It
must not see coin history, the later payment amount, or the recipient.

## What to build

A **Zark sidecar** next to OpenSSP, not a fork of OpenSSP.

1. **Process.** Run it as its own process under the network lock. The
   demo's co-signer is still in-process in each wallet window; the sidecar
   can start the same way. A standalone signer service follows once the
   swap flow works.
2. **Quote, reserve, exchange, confirm, seal, claim.** The wallet offers
   coins and wanted amounts. The sidecar reserves matching inventory and
   returns a signed quote. Each side proves and offers its coins, then
   confirms. The last confirmation **seals** every member in one signer
   commit before the reply. After the seal, no member can be cancelled.
   Each recipient claims independently. Fees stay zero, matching OpenSSP.
3. **Group seal at the signer.** Today each coin commits when its
   recipient issues, and the sender may cancel until then. Grouping adds
   a group digest, a confirmation command, refusal of recipient steps
   before the seal, at most one open group per coin, and a 32-member cap.
   Existing coins stay readable. The circuits and intent encoding do not
   have to change if `operation = H(group, index)` stays a wallet-chosen
   field already bound by the sender proof.
4. **Inventory.** The sidecar's treasury is an ordinary Spark wallet. It
   restocks by obtaining power-of-two leaves (OpenSSP swaps or faucet
   roots) and entering each through Go private. Those restocks are
   visible on Spark and must be attributed separately from private swaps.
   Received coins rejoin inventory only after recovery is saved.
5. **Exact-value coins, optional.** OpenSSP's on-demand split can turn
   one sidecar leaf into an exact amount plus change, then both enter
   Zark. That is a Spark-visible split just before the swap. Off by
   default.

Do not reuse the legacy `zark-spark-ssp` synthetic admission path for
this. Quotes, planning and the durable journal can be reused; settlement
must go through the real-proof signer.

## OpenSSP work that still matters here

These are the integration points this demo already hit. They stay relevant
when the sidecar sits next to OpenSSP.

- **Two projects.** `scripts/spark-regtest.py` start/stop target the
  development project `zark-spark`. The live chain is
  `zark-spark-acceptance`. `scripts/spark-dev.sh` is the safe wrapper:
  start acceptance explicitly, never reset it with `spark-regtest.py test`
  while wallets have pending operations, and stop acceptance **before**
  the container. A `docker stop` with a 1-second timeout SIGKILLs
  bitcoind and drops unflushed blocks.
- **Liquidity is root-shaped.** Incognito entry still rebuilds the leaf's
  node transaction as a deposit-root (`circuits/spark-receive-relations`).
  Split SSP children cannot enter until that relation, the observer and
  recovery accept ancestor chains. Until then the sidecar, like today's
  ATM, must hand out root notes or fail closed.
- **Operator agreement.** Public claims already wait for a 3-operator
  quorum. After a swap the three operators do not record the new leaf at
  the same moment. Any sidecar inventory check needs the same wait, not
  a single RPC.
- **Crash safety.** Journal the quote, frozen Initiate/Start bytes,
  transfer IDs and claim attempts before each irreversible call. A
  resumed swap must resend the same bytes. An unfilled swap that waits
  for operator expiry currently blocks the whole Public wallet
  (`swap_pending`); a sidecar must not do that to Incognito.
- **No operator patch in the deployed stack.**
  `integrations/spark/operator-overlay/` is an unmerged claim-payload
  experiment. Unmodified operators reject it. Do not depend on it.

## What each party would learn

| Party | Learns | Does not learn |
| --- | --- | --- |
| Spark operators | Entry, exit, and sidecar restocking | Private swaps and payments |
| OpenSSP | Public-mode swaps, as today | Private swaps |
| Zark sidecar | Coins and amounts it exchanged, their backing leaves, the wallet's claim key | Coin history, the later payment, the recipient |
| Co-signer | Coin handles, phases, which coins share a group | Claim keys (salted commitments) |

A stable per-profile claim key lets the sidecar link swaps by the same
wallet. Per-swap claim keys remove that link. Entry and exit still have
the demo's weaker disclosure: the co-signer can correlate the leaf with
the coin there.

## Suggested order

1. Native leaf values (drop the fixed Incognito denominations and the
   64,000-sat leftover in older fixtures).
2. Split-leaf entry, so OpenSSP children can become Zark coins.
3. Group seal and multi-coin payments.
4. Sidecar process and swap-then-pay on regtest.
5. Desktop swap preview and progress.

A combined swap-and-payment group, and hosting this next to Breez `sspd`
instead of OpenSSP, come after that. Proving cost for a multi-coin swap
is a separate document: [future-work-proving.md](future-work-proving.md).
