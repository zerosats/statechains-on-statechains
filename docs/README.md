# Future work

This demo is a local regtest research prototype. These notes record the
three integrations that would turn it into something a Spark wallet can
ship. They are plans, not claims about the current tree.

- [Spark SSP (OpenSSP)](future-work-ssp.md) — a Zark sidecar that swaps
  private coins the way OpenSSP swaps ordinary leaves.
- [Breez Spark SDK](future-work-breez-sdk.md) — fold the joint signer,
  proofs and Go-private / Go-public actions into `SparkWallet`.
- [Proving cost](future-work-proving.md) — stop proving 7–12 times for
  one SSP-to-user swap.

Read [PUBLIC-SSP-SWAPS.md](../integrations/spark/PUBLIC-SSP-SWAPS.md)
for what Public swaps already do.
