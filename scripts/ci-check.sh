#!/usr/bin/env bash
# Formatting, lints, and every test that needs nothing built beside it.
#
# The fast gate. Nothing here needs a wasm guest, Docker, or a network, so it is
# the job that should fail first when something is simply wrong.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

# The runtime's packages. The policy guest's (its component and the crates it
# shares with the wallet) are checked by ci-policy.sh, to their own standard,
# and need protoc to build.
RUNTIME=(-p enclave-runtime -p nitro-attestation -p nitro-nsm)

say "rustfmt"
cargo fmt "${RUNTIME[@]}" -- --check

# `--all-targets` so the lints cover tests and benches too, and `-D warnings`
# because a lint nobody has to fix is a lint that accumulates. `--no-deps`
# keeps threshold, which the runtime's wallet key builds on, to ci-policy.sh's
# standard.
say "clippy"
cargo clippy "${RUNTIME[@]}" --all-targets --no-deps -- -D warnings

say "unit tests"
cargo test "${RUNTIME[@]}" --lib
# The runtime's settings are parsed in the binary, whose tests `--lib` skips.
cargo test -p enclave-runtime --bin enclave-runtime

# Integration suites run only where they are named, and this one ran nowhere
# before. It is the boot machine — a release's key, its restarts, a new release —
# over the in-memory backend, so it needs no guest built.
say "boot machine"
cargo test -p enclave-runtime --test boot_version
