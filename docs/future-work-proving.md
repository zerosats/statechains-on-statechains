# Future work: proving cost and aggregation

A private handover today is two UltraHonk proofs in sequence: the sender
proves ownership, then the receiver verifies that sender proof recursively
and proves the claim. On the development M1, with the accelerated runtime
and 8 prover threads, those two proofs take about **17 seconds** together.
An SSP-to-user swap that reshapes several coins therefore proves and
verifies on the order of **7–12 proofs** (often more) before anyone can
pay. That is the main reason a private swap feels unlike a native Spark
swap.

This note is about reducing that, without giving the co-signer or the SSP
a coin's history.

## What a swap actually proves

Incognito coins are whole notes. Paying 40,960 sats from a wallet that
holds 32,768 + 16,384 + 16,384 is:

1. **Swap** with a Zark SSP: one 16,384-sat coin out, two 8,192-sat coins
   back. Three handovers, **six proofs**.
2. **Payment:** 32,768 + 8,192 to the recipient. Two handovers, **four
   proofs**.

Ten proofs, serially, is about three minutes at 17 s each. A messier
amount (40,000 = five binary notes, plus swap change) is 12–15 handovers.
Native Spark does the same reshape as **one** Swap V3 round trip.

Each handover is serial because
[`circuits/spark-lineage-relations/src/receiver.nr`](../circuits/spark-lineage-relations/src/receiver.nr)
calls `verify_sender` on the actual sender proof. The two proofs cannot
run at the same time in the current construction. Concurrent handovers on
one machine also do not help: one proof already uses every performance
core.

## Where the gates go

Measured Spark receiver (after the batched-nonce trim, suite in
`work/spark-suites/`): about 1.02M rows.

| Category | Rows | Share |
| --- | --- | --- |
| Recursive verification of the previous proof + VK hash | ~704k | 66–72% |
| Fixed-base secp256k1 muls | ~151k | ~14% |
| GLV variable-base muls | ~110k | ~10% |
| SHA-256 | ~82k | ~8% |
| Everything else | ~27k | |

With this `bb`, proving time tracks rows **used**, not the next power of
two. Trimming ~57k rows (digit recoding, SHA packing, batched nonces)
moved the receiver from 19.4 s to 19.2 s. Further SHA or config trims
are not worth a new suite.

The 704k-row recursive verifier is itself mostly a non-native BN254 KZG
MSM (~598k rows). That is the circuit-level research target, not the
leaf SHA checks.

## What this demo already did (keep these)

These are in the tree. Do not redo them as if they were new ideas.

- **8 prover workers**, fixture bound `1..=8`, env
  `ZARK_SPARK_PROVE_THREADS`. Default in the fixture is still 2; 4 is
  the sensible product default (about 28% faster than 2). 8 is another
  ~9% and takes every core, so keep it opt-in beside the regtest stack.
- **Accelerated runtime** (`runtime/fast-prover/`, hashes in
  `apps/desktop/runtime/spark/prover.mjs`): a direct witness executor
  (no `nargo` recompile) and `bb-cap15` with `BB_MSM_NEW=1`. Qualified
  only when those exact hashes match; otherwise stock `bb`. Every proof
  still verifies with stock `bb` against the pinned VKs. The binaries
  do not yet match the source-lock pins — that is remaining work, not
  a reason to turn the fast path off in the demo.
- **Launch fix:** bound the inherited `RLIMIT_NOFILE` before exec so
  each prover/verifier spawn is milliseconds, not a scan of ~10⁶
  descriptors. Do not cache a whole `ProverInstance`; it is
  witness-dependent.
- **Receiver under 2²⁰** and batched nonce check
  (`D0 + w·D1 = 0`, 128-bit Fiat–Shamir weight). Keep the old suite
  for existing coins.

Those changes took a live handover from ~52 s to ~17 s. They will not
take a 10-proof swap to something a user will wait through.

## Directions, largest first

### 1. One proof per handover (group / Candidate D)

Today each of the two circuits carries a ~704k-row verifier. If both
are ~1M rows, removing one verifier saves about 35% of combined rows,
roughly **1.5×**, not 2×. Profile the sender before relying on that
number (it has not been flamegraphed the way the receiver has).

The real design question is who can supply a merged proof's witnesses
without seeing the other party's secrets. Moving the recursion from
the receiver circuit into the sender circuit, or into a third wrapper,
can just relocate the 17 s. Replacing the recursive check with a
co-signer attestation changes the trust model and is not a drop-in.

Recipient-local work (witness gen, claim-key derivation) can overlap
the sender proof. Pre-proving the sender requires freezing the exact
recipient, intent and state bindings, plus a stale-state rule.

This is the first architectural change worth a new suite.

### 2. One proof per swap group

A swap is already a group of coins that seal together
([future-work-ssp.md](future-work-ssp.md)). Proving them independently
is what produces the 7–12 proof blast.

A group proof would show, in one statement:

- each offered coin is owned by the sender at the reserved intent;
- each returned coin is a valid issuance to the recipient's claim key;
- value in equals value out plus the authorized fee;
- the group digest `G` binds the members.

The co-signer already sees handles, amounts and the group. It must
still not see history. The SSP already sees the coins it exchanged. A
group proof that only talks about those coins' current statements —
not their predecessor proofs — is the privacy-compatible version.

Recursive verification of *every* predecessor inside one circuit is
the wrong shape: it would make the swap proof larger than the sum of
the handovers. Folding or an accumulator over prior certificates is
the point of direction 4.

Until a group proof exists, two product mitigations cut the proof
count without a new proof system:

- **Exact-value sidecar coins** (one out, one exact + change in)
  instead of a binary expansion.
- **Idle-time reshape**, like the SDK's leaf optimizer, so a payment
  is usually an exact cover (2–4 proofs) and the swap is off the
  critical path.

### 3. Native prover / MSM work (no new keys)

The prover spends a lot of wall time on commitments/MSMs. Faster
native MSM can change elapsed time without changing circuits or VKs,
if equivalence is checked. The IFMA path that helped on x86 does not
apply to Apple Silicon. Deposit-only accumulator specialization
applies only where the carried accumulator is constrained to zero;
it does not extend to recursive transfer predecessors.

This is worth a qualified `bb` rebuild that **matches the source
pins**, which the current fast binaries do not.

### 4. Folding / IVC

A longer-term option: incrementally verify the lineage so a swap
carries one updated accumulator instead of N recursive UltraHonk
proofs. Aztec's ClientIVC is the obvious candidate next to this
toolchain, but it is a new proof system, new suites, new verifier
keys and a deployment plan. Do not start it to shave a few seconds
off a single handover.

## Constraints any of the above must keep

- The co-signer verifies lineage **without** seeing prior transfers,
  amounts as Spark-native facts, or the receive leaf. A faster proof
  that dumps history into the signer is a regression.
- Never replace a constraint with an assumption. A batched or folded
  check needs a written soundness argument, like
  `work/spark-nonce-batch/SOUNDNESS.md` did for the nonce weight.
- A circuit change is a new suite with pinned hashes. Keep the old
  suites for existing coins. Check verifier-key and deployment
  implications before switching a live network.
- Every produced proof still verifies with stock `bb` against the
  pinned VK, including proofs from an accelerated or experimental
  prover.

## How to measure

Keep execute, prove, verify and process-launch times separate. The
handover benchmark path is `work/handover-bench/` in the development
tree; replay the retained Bob sender/receiver jobs before paying for
another live flow.

Baseline to beat, live share-release run on this demo path:

| Step | Time |
| --- | --- |
| One handover (sender + receiver) | ~17 s |
| Entry (two proofs + blind ECDSA + additive tweak) | ~16–30 s |
| Share-release exit | ~2 s |
| 10-proof swap-then-pay (estimated) | ~3 min |

A change is interesting if it takes the **swap-then-pay** path under
about 30 s, not if it trims 200 ms off a single `bb prove`.
