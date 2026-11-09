#!/usr/bin/env bash
# The S3 backend against a real S3 implementation: Object Lock, conditional
# writes and retained-version reads, which the anchor chain and the boot
# records are built on. And the background-task clients against LocalEmu's
# DynamoDB, EventBridge Scheduler and SQS.
#
# These tests start their own MinIO or LocalEmu through testcontainers — one per test, which
# is why they run single-threaded and take a while. That is also why this script
# does not call minio-up.sh: a store started here would sit unused.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

"$REPO/scripts/minio-image.sh" >/dev/null
"$REPO/scripts/localemu-image.sh" >/dev/null

say "MinIO integration"
cargo test -p enclave-runtime --test minio_integration -- --ignored --test-threads=1

say "background tasks against LocalEmu"
cargo test -p enclave-runtime --test tasks_aws -- --ignored --test-threads=1
