# Zark on Spark

A local regtest research prototype for private payments backed by Spark leaves.
Each wallet owns its leaves jointly with a blind Zark co-signer. A deposit
moves a leaf into Zark, private payments hand whole leaves between wallets
without any Spark transfer, and Go public releases a leaf back to an ordinary
Spark wallet. Ownership changes are authorized by real zero-knowledge proofs.
The ordinary (Public) wallet sends any amount, swapping leaves with the
regtest SSP for change, and withdraws 10,000/5,000/2,000-sat notes into Zark
the same way.

This is not production software. It runs only against a local Spark/OpenSSP
regtest stack. The co-signer can link a coin to its Spark leaf at entry and
exit, native Spark observation is trusted, and every desktop window runs inside
one test harness that holds all synthetic participants' private state.

## Run the demo

Requirements: Docker Desktop, Python 3.11+, Node.js 20+, Git, curl and the
pinned Rust toolchain (`rust-toolchain.toml`, installed by rustup). On macOS
the cb-mpc build also needs the Xcode command line tools. The full flow is
tested on Apple Silicon macOS. The scripts also target Linux on x86-64 or
arm64, which additionally needs clang, CMake and the Tauri WebKitGTK libraries
(`libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev`), plus QEMU emulation on
arm64 for the `linux/amd64` stack; Linux is not yet tested end to end.

On a fresh clone, prepare everything once:

```sh
python3 scripts/setup-demo.py
```

It downloads the pinned Nargo, BB and proving CRS and checks their hashes,
builds the proof suites and cb-mpc, fetches the Rust dependencies for the
offline worker build, and creates the regtest stack. Each finished step is
skipped on a rerun. The first stack build runs in a `linux/amd64` container
and takes a long time; see [the Spark integration](integrations/spark/README.md).

Then run the demo:

```sh
python3 scripts/run-demo.py
```

It starts the stack, opens Alice's and Bob's wallets on the `demo` network,
and stops the stack cleanly once both windows are closed. Ctrl-C closes every
window; each wallet first finishes its current operation. Other wallets and
networks: `python3 scripts/run-demo.py alice bob carol --network demo-2`.

The same steps by hand, with each wallet in its own terminal:

```sh
scripts/spark-dev.sh up --skip-helpers
ZARK_SPARK_NETWORK=demo ./run-wallet.sh --blinded alice
ZARK_SPARK_NETWORK=demo ./run-wallet.sh --blinded bob
scripts/spark-dev.sh down
```

`spark-dev.sh up` starts the stack without resetting it and builds the wallet
worker and desktop shell. Omit `--skip-helpers` the first time and after
changing the SDK helpers in `integrations/spark/sdk/`; `run-demo.py` does this
when the helpers are missing. `./run-wallet.sh --preview alice` opens the same UI
with synthetic data and no stack. The live check that `spark-dev.sh up` prints,
`scripts/check-spark-blinded-desktop.mjs <new-network>`, drives three wallets
headlessly through deposit, private payments and Go public.

## Layout

- `apps/desktop-tauri/`: the Tauri desktop shell and its web UI.
- `apps/desktop/runtime/spark/`: the Node launcher and the runtime that relays
  UI actions to the wallet worker.
- `integrations/spark/cosigner/`: wallet-side Spark signing, private transfers
  and the desktop wallet worker.
- `crates/signer/`: the durable blind Zark co-signer.
- `crates/protocol/`: shared canonical encodings, proof statements and verifiers.
- `circuits/`: the Noir proof programs used by the demo.
- `integrations/spark/`: the joint-claim and two-party ECDSA MPC crates, the
  Go RPC bridge, SDK helpers and the pinned regtest container.
- `scripts/`: regtest stack control, suite and prover preparation, live check.

## Test

```sh
cargo test --locked --workspace --all-targets
cargo test --locked --manifest-path integrations/spark/cosigner/Cargo.toml --features ecdsa-2p -- --test-threads=1
cargo test --locked --manifest-path apps/desktop-tauri/Cargo.toml
sh apps/desktop/test.sh
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Real-proof tests are ignored by default and need pinned proving tools and
suites; the live check needs the running regtest stack. Neither is implied by a
normal test pass. See [Contributing](CONTRIBUTING.md).

## Future work

Notes on the three integrations that would take this beyond a local
demo: [Spark SSP](docs/future-work-ssp.md), [Breez SDK](docs/future-work-breez-sdk.md)
and [proving cost](docs/future-work-proving.md).

Zark source is distributed under the [MIT license](LICENSE). Third-party
components retain their own notices and terms.
