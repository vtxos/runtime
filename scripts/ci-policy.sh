#!/usr/bin/env bash
# The policy guest: its tests, as wasm inside the fake host; its crates' tests on
# the host; clippy; and the component a release ships, built by Nix and run by
# the fake host through a wallet's life.
#
# Needs protoc for the build scripts, and Nix for the component and the policy's
# shell (the wasm clang, and `fake-host-run` to run its tests).

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

say "policy: tests, as wasm in the fake host"
# Run from guests/policy, whose cargo config targets wasm32-wasip2 and hands each
# test binary to `fake-host-run`. The same command a developer runs.
(cd guests/policy && nix develop "$REPO#policy" -c cargo test --locked)

say "policy: the crates it is built from"
cargo test -p enclave-client
cargo test -p threshold --features std,ecdh
cargo test -p ark --all-features

say "policy: clippy"
# `--no-deps`: the guest alone, as before the crates it uses joined this
# workspace and became members clippy would otherwise lint with it.
cargo clippy -p policy --no-deps -- -D warnings

say "policy: the component, built by Nix"
nix build .#policy --out-link result
sha256sum result/bin/policy.wasm

say "policy: linked by the runtime"
POLICY_WASM="$REPO/result/bin/policy.wasm" \
    cargo test -p enclave-runtime --test policy -- --ignored

say "policy: run by the fake host"
cargo clippy --manifest-path guests/fake-host/Cargo.toml --all-targets -- -D warnings
POLICY_WASM="$REPO/result/bin/policy.wasm" \
    cargo test --manifest-path guests/fake-host/Cargo.toml
