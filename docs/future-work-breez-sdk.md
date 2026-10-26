# Future work: Breez Spark SDK

This demo uses the Breez Spark SDK as an **unchanged library**, compiled
inside the OpenSSP container and linked by three small helper binaries.
A public wallet product would fold Zark into the SDK itself so a single
`SparkWallet` can hold ordinary leaves and private Zark coins, without a
desktop test harness or a Go fixture.

Pinned SDK revision: `vendor/breez-sdk`
`2472fdc0e136868eb10e5ad9f501a7e740080f04`
([sources.json](../integrations/spark/sources.json)). Helpers:
[`integrations/spark/sdk/`](../integrations/spark/sdk/).

## What the demo already does with the SDK

`sdk/build.py` does not compile or patch SDK sources. It type-checks and
links `send.rs` and `receive.rs` against the **retained** `libspark-*.rlib`
from OpenSSP's Breez e2e build, and it fails closed if that crate set is
ambiguous. `zark-ordinary-receive` is a separate Go test binary that talks
to the operators for Public deposit, Swap V3, observation and share-release
exit.

**Share-release send** (`sdk/send.rs`) is the important adapter:

- After Go public, the wallet holds `p = x_w + x_s`, which is both the
  leaf's Spark identity and its USER key.
- A `SparkSignerAdapter` runs the stock transfer flow over an inner
  `DefaultSigner`.
- The identity derivation path is answered with `p`. The leaf key reaches
  the inner signer only as Spark ECIES ciphertext the wallet seals to
  that inner identity.
- The private stdio port terminates at the **wallet**, never the blind
  Zark co-signer.
- The wallet supplies a durable transfer ID so a retry resumes the same
  Spark transfer.

Public sends and ATM swaps do **not** go through `sdk/send.rs`. They go
through the Go fixture (`ordinary_public_swap_test.go`). The SDK helper's
split refusal stays on the Go-public path only.

The SDK's own SSP daemon (`crates/spark-service-provider/sspd` on Breez
`main`) is **not** in the fork OpenSSP vendors. This demo's liquidity is
OpenSSP, not `sspd`.

## Why a helper binary is not an SDK integration

The current shape is a research boundary:

- The desktop worker is an ignored Rust test
  (`serve_blinded_wallet_regtest`) spawned by Node and wrapped in Tauri.
- Public observation, swaps and faucet funding live in Go, driven over a
  JSON pipe.
- Proof suites, the co-signer SQLite database and the network lock live
  in `work/zark-spark/blinded-networks/`, outside any SDK wallet store.
- Two windows on one machine share one in-process signer. That is not a
  mobile or multi-device model.

A Breez integration should look like any other Spark feature: the app
holds one wallet object, the SDK owns persistence and networking, and
Zark is a signing and proof backend behind `Signer`.

## How to integrate

Keep Spark's wire protocol and operators unchanged. Add a Zark backend
that the SDK calls the way it already calls `Signer` and the SSP.

### 1. A `Signer` that can be joint

Implement `spark::signer::Signer` for the joint identity / USER key,
reusing the demo's split:

| SDK request | Who answers |
| --- | --- |
| Identity public key | Joint `P` (wallet share + co-signer share) |
| Identity ECDSA (login, deposit, claim tweak) | Blind cb-mpc + additive receive, as today |
| Identity Schnorr (Spark auth challenge) | Two-party Schnorr over a parsed challenge only |
| New-leaf keys for a transfer the SDK creates | Wallet-local `DefaultSigner` (or equivalent), never the Zark co-signer |
| Leaf USER signing after share release | Wallet, once it holds `x_w + x_s` |

The hard rule from `send.rs` stays: the co-signer never sees a Spark
transfer package, a destination address, or a raw leaf secret.

### 2. Wallet methods that match the demo screens

Expose the same actions the desktop already has, on the SDK wallet:

- **Public:** current Spark send, receive, swap-with-SSP, and leaf
  optimization. Prefer the SDK's own swap client over the Go fixture.
- **Go private:** enter a leaf the Public wallet already holds. Today's
  ATM restriction (root-shaped 10k/5k/2k notes) is a demo limit, not an
  SDK one. The receive proof and observer have to accept the leaf the
  SDK actually holds, including SSP split children
  ([future-work-ssp.md](future-work-ssp.md)).
- **Incognito send / receive:** private handover. The receive address is
  the recipient's claim key. Offers can travel through the SDK's existing
  mailbox or an encrypted inbox the SDK hosts. The recipient claims
  automatically when online.
- **Go public:** share release, then the stock SDK send into this
  wallet's Public leaves.

Progress events matter: entry is ~16 s, a handover ~17 s, exit ~2 s on
the development machine with the accelerated prover. The SDK should
surface stage names, not a single blocking call.

### 3. Persistence the SDK already knows how to do

Move, do not reinvent:

- Co-signer database and `floor.witness` rollback guard into the SDK's
  authenticated data dir, with the same commit-before-response and
  recovery-before-acknowledgement rules.
- Per-coin journals, swap journals and the blocked-network flag into the
  SDK wallet store. An interrupted Go private or share-release exit must
  still block new work, not retry unsafely.
- Proof-suite manifests stay pinned. A wallet created against suite
  `z5i7n3_n` (or its successor) cannot silently load another VK.

One signer per network, not per UI window. On mobile that is one
background service or one in-process engine with a single lock.

### 4. Proofs and tools as SDK assets

The SDK would need to ship or download:

- the four pinned suites (ownership, receive, ordinary native exit, blind
  Schnorr auth);
- stock `bb` as the verifier;
- optionally the accelerated executor/prover, only when their hashes
  match the pins in `apps/desktop/runtime/spark/prover.mjs`.

Do not take a dependency on `nargo` at runtime. The demo's stock path
still recompiles the circuit on every `nargo execute`; the fast executor
exists specifically so a shipped artifact is enough.
([future-work-proving.md](future-work-proving.md).)

### 5. `sspd` as the Public SSP

Breez `main` already has `sspd`: a power-of-two pool, target counts per
denomination, restock through on-chain deposit trees, zero fees, up to
1,000 targets. Once Public sends go through the SDK, prefer `sspd` (or
OpenSSP behind the same Swap V3 client) and delete the Go swap fixture.

`sspd` still cannot swap Incognito coins. That remains the Zark sidecar
in [future-work-ssp.md](future-work-ssp.md). The interesting later
option is to host that sidecar next to `sspd` so one operator process
serves both Public leaf optimization and private coin optimization.

## What not to do

- Do not fork Spark's transfer, claim or swap RPCs.
- Do not put proof witnesses, claim secrets or `x_s` in SDK logs or
  analytics.
- Do not let the SDK's default signer derive the joint identity key from
  a seed. `P` is additive with the co-signer; a BIP32 path that produces
  `P` would let the wallet spend without it.
- Do not treat the desktop preview (`ZARK_PREVIEW=1`) or the synthetic
  worker as an SDK backend.

## Suggested order

1. Replace the Go Public fixture with SDK send / receive / swap calls
   behind the existing desktop actions, still on regtest. This proves
   the `Signer` adapter beyond share-release.
2. Lift the worker out of `cargo test --ignored` into a library the SDK
   (or a thin `zark-spark` crate) depends on.
3. Persist the co-signer and coin journals through the SDK store, with
   the rollback guard.
4. Expose Go private / Incognito send / Go public on `SparkWallet`.
5. Package proof assets and a mobile-sized prover profile (4 threads,
   one proof at a time; 8 threads is every core on the demo M1).
