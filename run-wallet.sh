#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Opens the Spark regtest prototype (`--blinded <profile>`) or the same UI with
# synthetic data (`--preview <profile>`); see scripts/spark-dev.sh.
exec "${ZARK_NODE:-node}" "$repo/apps/desktop/runtime/spark/launch.mjs" "$@"
