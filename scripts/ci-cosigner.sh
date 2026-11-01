#!/usr/bin/env bash
# The cosigner: its component's and its crates' tests on the host, clippy, and
# the component a release ships, built by Nix and run by the fake host through
# a wallet's life.
#
# Needs protoc for the build scripts, and Nix for the component.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

say "cosigner: tests"
cargo test -p cosigner -p enclave-client
cargo test -p threshold --features std
cargo test -p ark --all-features

say "cosigner: clippy"
# `--no-deps`: the cosigner alone, as before the crates it uses joined this
# workspace and became members clippy would otherwise lint with it.
cargo clippy -p cosigner --no-deps -- -D warnings

say "cosigner: the component, built by Nix"
nix build .#cosigner --out-link result
sha256sum result/bin/cosigner.wasm

say "cosigner: linked by the runtime"
COSIGNER_WASM="$REPO/result/bin/cosigner.wasm" \
    cargo test -p enclave-runtime --test cosigner -- --ignored

say "cosigner: run by the fake host"
cargo clippy --manifest-path guests/fake-host/Cargo.toml --all-targets -- -D warnings
COSIGNER_WASM="$REPO/result/bin/cosigner.wasm" \
    cargo test --manifest-path guests/fake-host/Cargo.toml
