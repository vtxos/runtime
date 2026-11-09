# Background tasks

A guest can schedule durable work for its tenant: once at a given time, or
recurring. The work is scheduled outside the enclave, through AWS, and run
inside it:

```text
  guest: enqueue ──► DynamoDB: the task, signed ──► EventBridge Scheduler
                                                          │ at its time
  guest: run-task ◄── runtime: verify, claim, run ◄── SQS ◄┘
```

The runtime keeps no clock for tasks. It records each task where an operator
can see it, makes a schedule for it, and runs whatever the queue delivers, once
it has checked it. A tenant with no due work needs no running guest instance.

## Enable

The guest must export `run-task`, and may import the queue interface defined in
[`wit/tasks/tasks.wit`](../wit/tasks/tasks.wit). There is no switch: tasks run
when the guest exports `run-task`. The guest is measured into PCR16, so its
exports already are the decision. A guest that exports it needs WebAuthn
authentication, or the runtime refuses to start.

Where tasks are scheduled comes from four image settings, measured into PCR0
like every other setting:

| Setting | What it names |
|---|---|
| `ENCLAVE_TASK_TABLE` | The DynamoDB table tasks are recorded in |
| `ENCLAVE_TASK_QUEUE_URL` | The SQS queue due tasks are delivered on |
| `ENCLAVE_TASK_SCHEDULE_GROUP` | The EventBridge Scheduler group tasks are scheduled in |
| `ENCLAVE_TASK_SCHEDULER_ROLE_ARN` | The role EventBridge Scheduler takes to send to the queue |

They come from `taskTable`, `taskQueueUrl`, `taskScheduleGroup` and
`taskSchedulerRoleArn` in [`deploy/nix/deployment.nix`](../deploy/nix/deployment.nix).
[`deploy/tofu`](../deploy/tofu/main.tf) creates the resources, prints the four
values as its `task_*` outputs, and grants the instance role exactly what the
runtime calls.

Set all four, or none. With none, a production enclave runs no background
tasks. The `testing` build, which the emulator image uses, keeps them in memory
instead, and loses them on restart.

| Limit | Value |
|---|---:|
| Attempts running at once, across tenants | 8 |
| Tasks per tenant | 64 |
| One attempt | 600 s |
| Attempts per occurrence | 5 |
| Payload, result | 64 KiB each |

None of these is a setting. An attempt gets minutes because work that drives a
round with an outside service waits on that service's schedule.

A tenant's attempts never overlap each other or its requests: each one holds the
tenant's lock, the same lock its requests take. A tenant that is busy when its
task arrives is tried again shortly, without spending an attempt. Guest linear
memory is not limited yet.

## Guest contract

During an authenticated interactive call, the guest can call:

```text
enqueue(id, payload, run-at, interval-ms) -> result
status(id)                             -> result<JSON record>
cancel(id)                             -> result
forget(id)                             -> result
```

The runtime supplies the tenant from the executing instance; none of these
accepts a tenant id. Anonymous calls and guest initializers have no queue
authority.

An id is a tenant-local idempotency key: 1–64 ASCII letters, digits, hyphens or
underscores. Repeating an enqueue with the same id, payload, time and interval
returns the original task; different input under that id is refused until it is
cancelled and forgotten.

`run-at` is Unix time in milliseconds; zero, or any past time, means now. An
optional interval makes the task recurring. It must be a whole number of
minutes, at least one: the smallest rate EventBridge Scheduler has. Use the
payload as the durable request where you can: writing a separate application
file and enqueueing are **not** one transaction.

`status` returns JSON:

| Field | Meaning |
|---|---|
| `status` | `pending`, `running`, `completed`, `failed` or `cancelled` |
| `run_at`, `interval_ms` | As enqueued |
| `run_id` | The latest occurrence's run id, once one has fired |
| `attempts` | The latest occurrence's attempts |
| `result` | The latest occurrence's result, once it completed, as an array of byte values |
| `error` | The latest attempt's error, cut to 512 characters |

A recurring task stays `pending` between occurrences. A one-time task becomes
`completed` or `failed` with its only occurrence.

When a task is due, the runtime calls this export:

```text
run-task(task-id, payload) -> result<result-bytes, error-string>
```

It is not an HTTP endpoint. It runs in a fresh instance that sees the tenant's
directory as `/`, under a deadline. Nothing in memory outlives the call. A
missing tenant directory is a failure, never recreated.

Background code can read task status, but cannot enqueue, cancel or forget: an
authenticated interaction grants standing authority to run the work later, and
background work cannot grant itself more. Revoking a passkey does not cancel
its tenant's schedules; cancel them. Tasks run the currently approved guest
after an upgrade, so keep payloads compatible, or cancel affected tasks before
deploying a guest that cannot read them.

## How a task runs

1. **Enqueue.** The runtime signs the task and records it as `scheduling`. It
   then makes its trigger and marks it `scheduled`. The trigger is a schedule:
   `at(...)` for a one-time task, deleted once it fires, or `rate(...)` for a
   recurring one. A one-time task due within fifteen minutes skips the
   scheduler and goes straight on the queue, delayed until its time.
2. **Fire.** At its time, the scheduler puts a small message on the queue:
   which task, and when it was due. The message carries no payload and no
   authority.
3. **Receive.** The runtime long-polls the queue. Each message it receives is
   hidden for fifteen minutes while its attempt runs.
4. **Check.** The task named must be in the table and signed with its tenant's
   key, with its payload sealed to the same key. It must not have been
   cancelled, finished or replaced. A message before its time is dropped.
5. **Claim.** The occurrence is claimed with a conditional write, which carries
   a lease. An occurrence already finished is a second delivery, and is dropped.
6. **Run.** The guest's `run-task` runs. Whatever it wrote reaches the tenant's
   anchor, whether it succeeded or not.
7. **Record.** The outcome is recorded with a conditional write. Then the
   message is deleted, or released for the next attempt. Only then is a wake the
   run raised delivered.

## What the host can and cannot do

The table, the scheduler and the queue are reached with the instance's role,
which the parent holds too. So the parent can read, write and delete all of
them.

| The host tries to | Result |
|---|---|
| Forge a task, or change one | Refused: it is not signed with the tenant's task key, derived from the tenant's key ([`runtime/src/tenant.rs`](../runtime/src/tenant.rs)) |
| Read a payload or a result | It cannot: both are sealed to the tenant's key. Only the metadata is in the clear: the id, the times, the state, the attempts and the error |
| Run a task early | Refused: a delivery is checked against the enclave's own clock |
| Replay an occurrence that finished | Its record absorbs it. If the host rolls the table back too, the task runs again |
| Revive a cancelled task by rolling the table back | The same as a replay |
| Delete or delay a schedule, a message or a record | Denial of service, which it can always do. The alarms and the table show it |

So: **every task must be harmless if it runs twice, or late.** Delivery is at
least once whatever the table says. A handler deduplicates its effects by run id
and checks its own sealed state before acting.

## Retries and outcomes

The `task-id` passed to `run-task` is the run id, **not** the id the task was
enqueued under:

```text
<id>:<generation>:<occurrence>      e.g. nightly-sync:9f86d081884c7d659a2feaa0c55ad015:1793534400000
```

`generation` is 32 hex digits minted at enqueue. `occurrence` is when the
occurrence was due, in Unix milliseconds. An id cannot contain `:`, so the
enqueued id is everything before the first `:`. The run id stays the same across
retries of one occurrence, and changes for the next occurrence or for a task
enqueued again after `forget`. Deduplicate effects by the whole run id. Commit
filesystem writes before returning success. External effects need their own
idempotency.

- **A failed attempt** is tried again after 2, 4, 8 and 16 seconds. After five,
  the occurrence has failed. A one-time task fails with it. A recurring task does
  not: its next occurrence fires as scheduled. A guest error, a trap and the
  deadline are handled alike.
- **An attempt the enclave died in.** Its message comes back once it is no
  longer hidden, and the occurrence is claimed again once its lease runs out.
  That attempt counts, so a task that brings the enclave down fails after five
  attempts instead of looping. A message received fifty times without finishing
  is moved to the queue's dead-letter queue.
- **Missed occurrences** of a recurring task fold into one: the scheduler fires
  once for the time that passed.
- **Cancel** stops future runs. A task already finished stays as it is. An
  attempt already running is not interrupted, but its outcome no longer finishes
  the task.
- **Forget** removes a finished task, freeing its id and its quota, but never one
  with an attempt running.
- **Occurrence records** expire thirty days after their last write.

## When the owner has not signed in

A task can be checked and run only once its tenant is attached, because its keys
come from the tenant's key. When a release restarts, it re-attaches the tenants
whose keys it kept for background work, so their tasks keep running. **A new
release has kept none.** An occurrence that comes due before its owner signs in
to it is recorded as `waiting-for-owner`. When the owner signs in, the latest
waiting occurrence of each task is sent again, standing in for any older ones.
A waiting task cannot wake its owner either: device registrations are on the
tenant's pool. The table shows which tenants are waiting, so check it before
cutting a release.

## Consistency

The table is the record, the scheduler is the trigger and the queue is the
buffer. Each task is written to the table first, and everything converges on it:

- **Create and cancel** are three steps each, recorded in the task's state
  (`scheduling`, `cancelling`). Every five minutes, the runtime finishes any left
  half done for over a minute.
- **A missing schedule** for a recurring or future task is made again from the
  signed task. A one-time task whose firing never arrived within an hour of being
  scheduled is sent again.
- **An orphaned schedule**, left behind by a forgotten task, fires into nothing
  and is removed.

## Seeing what is scheduled

Every task is in the table, under its tenant's partition:

| Item | Key | Holds |
|---|---|---|
| A task | `T#<tenant>` / `TASK#<id>` | `state`, `run_at`, `interval_ms`, `schedule`, the signed task, `updated_at` |
| An occurrence | `T#<tenant>` / `RUN#<id>#<generation>#<due time>` | `state`, `attempts`, `error`, `updated_at`, the sealed result |

The `by-state` index answers by state, for example every scheduled task:

```sh
aws dynamodb query --table-name "$TASK_TABLE" --index-name by-state \
  --key-condition-expression 'state_key = :s' \
  --expression-attribute-values '{":s":{"S":"task#scheduled"}}'
```

The other values are `task#scheduling`, `task#cancelling`, `task#cancelled`,
`task#done` and `task#failed`, and for occurrences `run#running`, `run#retry`,
`run#completed`, `run#failed`, `run#waiting-for-owner` and `run#skipped`.

The schedules themselves are in the scheduler group. Two CloudWatch alarms watch
the queue: one for a message set aside in the dead-letter queue, and one for due
tasks waiting over half an hour, which means the enclave is down or cannot keep
up. Neither has actions attached; add your own to be paged.

## HTTP example

The example guest exposes these authenticated application routes:

| Request | Behavior |
|---|---|
| `POST /tasks/<id>` | Enqueue the body as the task payload; returns 202 |
| `GET /tasks/<id>` | Read that tenant's task status |
| `DELETE /tasks/<id>` | Cancel the task |
| `DELETE /tasks/<id>/forget` | Remove a finished task |

Optional `x-task-run-at` and `x-task-interval-ms` headers set the time and the
interval. The callback writes one durable result file per run id inside the
tenant's `/http-example/tasks/` directory, returning an existing result on retry.
Its `fail`, `spin` and `check-authority` payloads exercise retries, the deadline
and the rule that background code cannot authorize more work.

Build and test:

```sh
cargo build --manifest-path examples/guest-http/Cargo.toml --release --target wasm32-wasip2
# One serve_auth test drives the real client binary as a subprocess. Without it
# that test skips with a notice instead of failing, which reports green for a
# test that never ran.
cargo build --release -p enclave-runtime --features testing --bin passkey-client
cargo test -p enclave-runtime --lib tasks::tests -- --include-ignored
# The whole suite, deliberately unfiltered: a name filter here silently stopped
# covering this feature once a second scheduling test was added under a
# different name.
cargo test -p enclave-runtime --test serve_auth -- --include-ignored
```

The queue's own tests run against an in-memory table, scheduler and queue,
playing the host by changing what is stored.

The AWS clients run against [LocalEmu](https://github.com/localemu/localemu),
an open-source fork of LocalStack's community edition that serves DynamoDB,
EventBridge Scheduler and SQS on one endpoint ([`runtime/tests/tasks_aws.rs`](../runtime/tests/tasks_aws.rs)).
The tests cover the table's conditional writes and its index, hiding, releasing
and delaying messages, a schedule firing into the queue, and a whole task from
enqueue to recorded outcome:

```sh
scripts/localemu-image.sh    # the image, pinned by digest
cargo test -p enclave-runtime --test tasks_aws -- --ignored --test-threads=1
```

LocalEmu fires a schedule with its input unchanged, as AWS does, but leaves
`<aws.scheduler.scheduled-time>` unfilled where AWS puts the firing's time. So
the tests check that a firing arrives with the task's message, and drive the
consumer with the occurrence as AWS delivers it.

Inside the emulator, step `6/8` of [`deploy/qemu-nitro/run-e2e.sh`](../deploy/qemu-nitro/run-e2e.sh)
schedules work through the real passkey client and waits for it to finish, with
the in-memory backend.
