# Any-amount Public sends and ATM-style moves to Incognito

## Model

- **Public** is an ordinary Spark wallet that sends any whole-sat amount. It
  uses an exact set of up to 4 leaves when one adds up. Otherwise it picks
  the fewest covering leaves and asks the SSP (Swap V3) for
  `[amount] + change`.
- **Incognito** holds only 10,000 / 5,000 / 2,000-sat notes. Its rules are
  unchanged.
- **Public → Incognito is an ATM withdrawal** (`goPrivate {amountSat}`). A
  Public root leaf of that value moves as-is. Otherwise the SSP swaps Public
  leaves for that value. Only a returned leaf that passes the strict root
  shape check (`atm::entry_shape`, mirroring `controller.rs`) enters. Any
  other leaf stays on Public, and the move fails with `no_cash_leaf`.
  `goPrivate {leaf}` remains for existing root notes.

## Decisions

- **Root-leaf rule relaxed only for Public claims.**
  - `public_claim` and `ordinaryPublicObserve` trust a 3-operator quorum
    (COMPLETED, AVAILABLE, our owner and signing key, equal values). That is
    the standard Spark wallet trust model.
  - Anchor and root checks exist only because Incognito entry evidence binds
    the root's on-chain anchor. Entry keeps the strict `ordinaryObserve`.
  - Split leaves inside Incognito are out of scope; they would need a
    proof/circuit change.
- **SSP output is verified, never assumed.**
  - The fee must be 0.
  - Reported total and target amounts must match the request.
  - Every claimed leaf must be owned by Public, sent by the swap's SSP
    identity, and agreed by all 3 operators.
  - Each target must arrive as its own leaf, and the remaining leaves must
    sum exactly to the change. The SSP may pay change in several leaves (seen
    live: 7,000 + 2,000 + 1,000).
  - A mismatch is claimed but never spent (`swap_mismatch`).
- **Crash safety.**
  - Rust journals each swap (`profile/public/swaps/<id>.json`) and payment
    (`profile/public/sends/<transfer>.json`) before any fixture call. The
    payment's transfer ID and inbox entry name are fixed up front.
  - Go freezes the exact Initiate and Start requests before sending them, and
    retries resend the same bytes.
  - Resume happens in `background()` and before every Public operation.
  - A swap whose primary was never frozen is abandoned. A dead primary
    (EXPIRED or RETURNED) is abandoned.
  - Three failed counter-transfer claims pause the network (`publicSwap`).
  - Journal directories are created on first save, so existing profiles load
    unchanged. Envelope v2 adds `leaves`; v1 still loads.
- **Privacy.** The SSP links input leaves to output leaves. That is
  acceptable on Public, but it is a correlation handle at the ATM step.
- **`sdk/send.rs`'s split refusal is untouched.** It is the go-Public
  share-release path, not the Public wallet.

## Regtest SSP liquidity

`spark-dev.sh up` tops the SSP up to 3 wallet-created root leaves each of
10,000 / 5,000 / 2,000 (`ssp_ladder`, regtest only, idempotent, about 4 s).
SSP split children never pass the entry shape check.

## Known limitations

- While an unfilled swap waits for operator expiry (up to about 5 minutes),
  new Public operations are refused with `busy` / `swap_pending`.
- If an SSP fill succeeded but its response was lost, and the primary is
  later returned, the SSP's counter transfer is not claimed. Spark expires it
  back to the SSP.
- If the SSP runs out of root notes, it pays with split leaves. The move then
  stops with `no_cash_leaf`, and the value stays on Public.
- The Tauri window was not exercised by hand. The UI is covered by
  mock-bridge and model tests.
