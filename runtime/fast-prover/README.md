# Accelerated proving runtime

The demo's optional runtime-w8 profile uses two patched tools. Their binary
hashes are pinned in `apps/desktop/runtime/spark/prover.mjs`; any other build
falls back to stock BB.

- The witness executor applies `witness-fast-gzip.patch` to Noir commit
  `75061fab15986eedee4e7d9104ff87dd9fa4ca10`.
- The macOS prover applies `barretenberg-cap15.patch` to Aztec commit
  `49a592109ec4f18d79212b43d621891aaf36f7b6`.

Pinned BB dependency revisions used by that build:

| Dependency | Commit |
| --- | --- |
| gtest | `b796f7d44681514f58a683a3a71ff17c94edb0c1` |
| benchmark | `7638387d2727853d970fc9420dcf95cf3e9bd112` |
| libdeflate | `96836d7d9d10e3e0d53e6edb54eb908514e336c4` |
| httplib | `5c00bbf36ba8ff47b4fb97712fc38cb2884e5b98` |
| nlohmann_json | `9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03` |
| tracy | `5d542dc09f3d9378d005092a4ad446bd405f819a` |
| msgpack-c | `c0334576ed657fb3b3c49e8e61402989fb84146d` |
| lmdb | `ddd0a773e2f44d38e4e31ec9ed81af81f4e4ccbb` |

`scripts/prepare-spark-fast-runtime.py` authenticates an ownership suite and
writes a runtime profile for explicitly hashed binaries. Recompiling a tool can
change its hash; a new build needs new pins, never a bypass of the suite,
circuit source or verifier checks. Every proof is still verified with stock BB
against the pinned verification keys.
