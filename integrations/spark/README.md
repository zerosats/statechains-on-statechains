# Zark on Spark: regtest integration

This directory holds everything the desktop demo needs beyond the shared Zark
crates: a pinned local Spark/OpenSSP regtest stack, wallet-side Spark signing,
the MPC protocols that let a wallet and the blind Zark co-signer act as one
Spark USER key, and the desktop wallet worker.

## Trust model

This is a research prototype, not a custody design. The co-signer may link a
coin to its Spark leaf at entry and exit. ECDSA digests, nonce coordinates,
ECIES headers and decryption requests expose correlation handles. Private
payments hand over whole leaves without mutating them, but the co-signer
still tracks each coin's handover chain. Native Spark observation is a
trusted boundary: a dishonest configured source can lie about live state.
Every desktop window runs inside one test harness that holds all synthetic
participants' private state, so separate windows are not an isolation
boundary.

## Contents

- `sources.json`, `Dockerfile`: pinned OpenSSP, Spark, Breez SDK and LDK
  sources and the `linux/amd64` toolchain image. The local operator
  configuration enables `spark.so.mpc_transfer.enabled`; every build verifies
  revisions and rejects unrelated source edits.
- `cosigner/`: wallet-side shares, joint identity signing and decryption,
  additive receive, private transfers with real proofs, share-release exit,
  and the desktop worker (`private_transfer::real_fixture::live_receive::desktop`).
- `joint-claim/`, `ecdsa-2p/`: garbled-circuit and two-party ECDSA protocols
  for the joint identity key. `ecdsa-2p` links cb-mpc, built by
  `scripts/build-cbmpc.sh` (run by `scripts/setup-demo.py`).
- `rpc/`: the Go bridge to Spark operators and the native fixture driven by
  the worker (`TestOrdinaryReceiveNativeFixture`).
- [PUBLIC-SSP-SWAPS.md](PUBLIC-SSP-SWAPS.md): any-amount Public sends, SSP
  change, and ATM-style moves into Incognito.
- `sdk/`: the `zark-sdk-send`, `zark-sdk-receive` and `zark-ordinary-receive`
  helpers, built inside the container by `sdk/build.py`.
- `operator-overlay/`: an unmerged operator patch for the versioned
  independent-share claim payload. `python3 scripts/spark-regtest.py
  claim-overlay-prepare` applies it to a separate ignored source export; it is
  not deployed and unmodified operators reject the payload.

## Regtest stack

Use Python 3.11+, Git and a running Docker daemon as a regular user. The first
setup builds the image and services and creates the `zark-spark-acceptance`
project that the demo uses. `scripts/setup-demo.py` runs these commands when
that project does not exist yet:

```sh
python3 scripts/spark-regtest.py init
python3 scripts/spark-regtest.py image-build
python3 scripts/spark-regtest.py test
```

`spark-regtest.py test` runs upstream's acceptance suite and keeps that
project's data. Afterwards, `scripts/spark-dev.sh up` and `down` resume and
stop it without resetting the chain; `status` reports the container, chain
height and helpers. Do not run `spark-regtest.py test` again while a wallet
network has pending operations.

The fixture runs in one `linux/amd64` container, including on Apple Silicon,
so initial builds are slow. The toolchain image needs 12 GiB free and service
builds 8 GiB; a watchdog cancels builds below 4 GiB. Services bind to the
container's loopback network and publish no host ports. Sources, service data
and wallet state live under ignored `work/zark-spark/`.

## Desktop worker

`./run-wallet.sh --blinded <profile>` builds the cosigner's ignored
`serve_blinded_wallet_regtest` test and runs it as the wallet worker behind
the Tauri shell. `ZARK_SPARK_NETWORK` (default `demo`) selects a wallet network
under `work/zark-spark/blinded-networks/`; profiles on the same network can pay
each other. Each profile has its own lock, and a network lock serializes every
mutating operation. A network refuses to open if its pinned flags or proof
suites change, because its journals are bound to them.

Closing a window drains the current operation. An operation that did not
complete blocks further operations and shows the last completed balances; the
app offers no reset or replacement funding. Existing networks and their
pending operations must be reconciled, never deleted.

## Proofs

The worker requires four proof suites (ownership, receive, ordinary native
exit and blind Schnorr auth) in `work/spark-suites/`.
`scripts/build-spark-ownership-suite.py` builds one per run with pinned Nargo,
BB and CRS (`--receive`, `--ordinary-native`, `--auth`, or no flag for
ownership) and never replaces an existing suite, because wallet networks are
bound to their manifests. `scripts/setup-demo.py` downloads the pinned tools
into `work/tools/` and builds whichever suites are missing; the tool pins are
in `runtime/toolchains.json`.

Proving uses stock BB unless the accelerated runtime-w8 profile is present
and its executor and prover match the hashes in
`apps/desktop/runtime/spark/prover.mjs`.
`scripts/prepare-spark-fast-runtime.py` writes such profiles; the patches the
binaries were built from are in `runtime/fast-prover/`. Either way, every proof
is verified with stock BB against the pinned verification keys.

## Tests

```sh
cargo test --locked --manifest-path integrations/spark/cosigner/Cargo.toml --features ecdsa-2p -- --test-threads=1
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Ignored tests need explicit tools and inputs:

- `private_transfer::real_fixture::real_proof_alice_bob_carol_*` run real
  sender, receiver and recovery proofs through the co-signer on a signed
  synthetic Spark prefix (`ZARK_SPARK_REAL_SUITE`; the manifest pins the tools).
- `real_fixture::receive::real_proof_joint_receive_mpc_restart_and_dual_recovery`
  adds `ZARK_SPARK_RECEIVE_SUITE` and covers restart and both recoveries.
- `blind_auth_tests::real_proof_journal_signs_spark_challenge_through_engine`
  proves a blind Schnorr operator login (`ZARK_NARGO`, `ZARK_BB`, `ZARK_CRS`).
- `receive::additive_tests` checks ECIES against Spark's Go library
  (`ZARK_SPARK_ECIES_GO`).
- `joint_identity::tests` has two slow MPC replay tests.
- `serve_blinded_wallet_regtest` is the desktop worker itself.

`node scripts/check-spark-blinded-desktop.mjs <new-network>` is the live
end-to-end check: three wallets on a new network go through deposit, private
payments, Go public and a restart. `cosigner/examples/receive-custody-audit.rs`
re-verifies the public transactions a coin directory retains, and the
standalone drivers in `cosigner/interop/` check emitted vectors against
unmodified Spark libraries.
