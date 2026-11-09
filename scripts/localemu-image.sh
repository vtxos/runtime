#!/usr/bin/env bash
# The LocalEmu image the background-task integration tests run on, pinned by
# digest: the release `runtime/tests/tasks_aws.rs` was checked against.
#
# LocalEmu is an open-source fork of LocalStack's community edition, which was
# archived; it serves DynamoDB, EventBridge Scheduler and SQS on one endpoint.
# Tagged locally so the tests name a fixed image, never `latest`.
set -euo pipefail

VERSION=1.3.2
DIGEST=sha256:c9d08e1d2533e405b43301868e319085523d1035e436e2abfac305293e11f684
IMAGE="enclave-runtime/localemu:$VERSION"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker pull "localemu/localemu@$DIGEST" >&2
    docker tag "localemu/localemu@$DIGEST" "$IMAGE"
fi
echo "$IMAGE"
