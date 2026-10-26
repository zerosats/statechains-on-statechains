#!/bin/sh
# Local verification only; no CI service or network access is required by default.
set -eu
audit_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$audit_root"
if command -v cargo >/dev/null 2>&1; then
    audit_cargo=$(command -v cargo)
else
    audit_cargo=
    for audit_candidate in "$HOME"/.rustup/toolchains/1.95.0-*/bin/cargo; do
        if test -x "$audit_candidate"; then audit_cargo=$audit_candidate; break; fi
    done
    if test -z "$audit_cargo"; then
        echo 'Rust 1.95.0 must be installed and cargo available on PATH.' >&2
        exit 1
    fi
fi
audit_bin=$(dirname "$audit_cargo")
PATH="$audit_bin:$PATH"
export PATH
if test -d "$audit_root/work/cargo/registry"; then
    CARGO_HOME="$audit_root/work/cargo"
    export CARGO_HOME
fi
if test -d /Library/Developer/CommandLineTools; then
    DEVELOPER_DIR=/Library/Developer/CommandLineTools
    export DEVELOPER_DIR
fi
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$audit_root/work/implementation-target}"
export CARGO_TARGET_DIR
# Crates outside the workspace, each with its own lockfile. The cosigner is
# listed separately because its checks need the ecdsa-2p feature.
audit_standalone='integrations/spark/joint-claim integrations/spark/ecdsa-2p apps/desktop-tauri'
audit_action=${1:-check}
case "$audit_action" in
    noir) cd "$audit_root/circuits/relations"; exec "$audit_root/work/tools/nargo" test ;;
    check|test|build) exec "$audit_cargo" "$audit_action" --workspace --all-targets --locked --offline ;;
    test-protocol) exec "$audit_cargo" test -p zark-protocol --all-targets --locked --offline ;;
    test-signer) exec "$audit_cargo" test -p zark-signer --all-targets --locked --offline ;;
    test-cosigner) exec "$audit_cargo" test --manifest-path integrations/spark/cosigner/Cargo.toml --features ecdsa-2p --locked --offline -- --test-threads=1 ;;
    build-release) exec "$audit_cargo" build --workspace --release --locked --offline ;;
    clippy)
        "$audit_cargo" clippy --workspace --all-targets --locked --offline -- -D warnings
        for audit_crate in $audit_standalone; do
            "$audit_cargo" clippy --manifest-path "$audit_crate/Cargo.toml" --all-targets --locked --offline -- -D warnings
        done
        exec "$audit_cargo" clippy --manifest-path integrations/spark/cosigner/Cargo.toml --all-targets --features ecdsa-2p --locked --offline -- -D warnings ;;
    fmt|format)
        audit_check=
        if test "$audit_action" = fmt; then audit_check=--check; fi
        "$audit_cargo" fmt --all $audit_check
        for audit_crate in $audit_standalone integrations/spark/cosigner; do
            "$audit_cargo" fmt --manifest-path "$audit_crate/Cargo.toml" $audit_check
        done ;;
    fetch)
        "$audit_cargo" fetch
        for audit_crate in $audit_standalone integrations/spark/cosigner; do
            "$audit_cargo" fetch --manifest-path "$audit_crate/Cargo.toml"
        done ;;
    lock) exec "$audit_cargo" generate-lockfile --offline ;;
    *) echo 'usage: check-local.sh check|test|test-protocol|test-signer|test-cosigner|build|build-release|clippy|fmt|format|noir|fetch|lock' >&2; exit 2 ;;
esac
