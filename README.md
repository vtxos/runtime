# Aegira

**Run an ordinary WebAssembly component inside an AWS Nitro Enclave, where the enclave itself serves every standard WASI call, down to the hardware clock and the security module.**

Write the guest with plain `std`. `SystemTime::now()` reads the Nitro PTP hardware clock, `getrandom` reads the Nitro Security Module, `std::fs` writes to a store that is encrypted before anything reaches S3, and requests arrive over TLS terminated inside the enclave. The guest never touches a device path, a key or a certificate.

WASI has no way to reach a person between requests, or to sign with a key the code never holds, so the runtime adds [WIT capabilities](#capabilities-beyond-wasi): **`enclave:notify`** wakes the owner's phone without revealing why, **`enclave:tasks`** runs durable work while no client is connected, scheduled through AWS and run inside the enclave, and **`enclave:signer`** signs with a wallet key split between the owner's app and the enclave, so neither signs alone.

Every party that relies on the enclave checks the same two measurements: PCR0 for the runtime image and its configuration, PCR16 for the guest. KMS checks them before releasing a release's own key, and a native app before sending its half of the key that opens its tenant's data.

**What is in this repository.** The runtime, and what a product needs to build on it:

- the [WIT contracts](wit/), also as a crate a Rust guest depends on for its bindings;
- small [example guests](examples/): HTTP with tasks and notify, bidirectional gRPC, a guest that signs, and SQLite;
- a [development enclave](#try-it-locally) that boots the real image in QEMU with any guest;
- a [client library for native apps](#a-client-for-native-apps): the attested connection, sign-in, and the app's half of the wallet key.

It holds no application guest. A product's guest, and the messages it speaks with its app, live with the product.

> **Pre-1.0, under active correctness review.** The runtime, its capabilities, the KMS recipient flow and the deployment tooling are implemented and tested, including end to end in an emulated enclave. Validation on real Nitro hardware and against live KMS and AWS End User Messaging Push is outstanding, as is storage garbage collection. This is not a production-readiness claim.

## Contents

- [Plain WASI, enclave hardware underneath](#plain-wasi-enclave-hardware-underneath)
- [One clock, one entropy source, one identity](#one-clock-one-entropy-source-one-identity)
- [Capabilities beyond WASI](#capabilities-beyond-wasi)
- [Try it locally](#try-it-locally)
- [Trust boundaries](#trust-boundaries)
- [Measured boot and key release](#measured-boot-and-key-release)
- [Verifying the enclave from a client](#verifying-the-enclave-from-a-client)
- [A client for native apps](#a-client-for-native-apps)
- [Storage](#storage)
- [Configuration](#configuration)
- [Build, test, and deploy](#build-test-and-deploy)
- [Limits and remaining work](#limits-and-remaining-work)
- [Repository guide](#repository-guide)

## Plain WASI, enclave hardware underneath

The runtime links the standard WASI 0.2 interfaces and serves each one from inside the enclave boundary:

| The guest writes | WASI interface | What answers it inside the enclave |
|---|---|---|
| `SystemTime::now()` | `wasi:clocks/wall-clock` | The Nitro **PTP hardware clock** (`/dev/ptp0`, disciplined by Amazon Time Sync), not the system clock the parent can set |
| `getrandom`, `OsRng`, key generation | `wasi:random/random` | The **Nitro Security Module**, read directly on every call with no DRBG in between |
| Hash-table seeding | `wasi:random/insecure-seed` | A fresh NSM draw for every instance |
| An HTTP handler | `wasi:http/incoming-handler` | TLS terminated **inside** the enclave, behind a gate that admits only requests signed with the tenant's wallet share; the runtime sets the caller's tenant in `x-enclave-tenant` |
| A gRPC service | `enclave:rpc/service` ([this runtime's WIT](wit/rpc/rpc.wit)) | The same TLS and gate, with gRPC ended by the runtime: the guest gets each call's messages as a stream and answers on another, and never sees HTTP |
| An outbound HTTP request | `wasi:http/outgoing-handler` | **Denied by default.** Exact origins named in the measured image are allowed, verified against web PKI roots compiled into the image |
| `std::fs` | `wasi:filesystem` | A per-tenant ZFS dataset on an encrypted disk, anchored in S3 ([how](docs/STORAGE.md)) |
| `println!`, `eprintln!` | `wasi:cli/stdout`, `stderr` | Bounded, structured log records tagged `guest`, optionally forwarded to CloudWatch |
| `std::env::var` | `wasi:cli/environment` | The settings the guest file carries, measured into PCR16; nothing from the runtime's environment |
| stdin, raw sockets | `wasi:cli/stdin`, `wasi:sockets` | Stdin is closed. Sockets are linked so guests instantiate, but every address is refused |

`wasi:clocks/monotonic-clock` and `wasi:random/insecure` keep wasmtime's host-backed defaults. They measure durations and drive non-cryptographic generators; they never supply a timestamp or a secret.

Inbound HTTP/2 is negotiated per connection, so a guest can answer a bidirectional gRPC stream while it is still arriving ([streaming](docs/STREAMING.md), [`guest-grpc`](examples/guest-grpc/), which exports `enclave:rpc/service`).

There is no enclave SDK. The [example guest](examples/guest-http/src/main.rs) is `std`, `wstd` and `wit-bindgen`, and the same component bytes, and therefore the same PCR16, run in the QEMU development enclave and on Nitro.

## One clock, one entropy source, one identity

The runtime opens each trusted device once at boot and hands that one handle to everything that needs it, the guest's WASI imports and the runtime's own subsystems alike. A timestamp the guest reads is the one a task's delivery is checked against, and every secret in the system comes from the same device.

### One clock

An enclave has no NTP. The hypervisor sets its system clock, and the parent instance controls the hypervisor. The runtime instead reads the Nitro card's PTP hardware clock through the POSIX dynamic-clock interface, and every reader shares one adapter:

| Reader | What depends on it |
|---|---|
| Guest `wasi:clocks/wall-clock` | Every `SystemTime::now()`, including expiry checks in guest code |
| Filesystem `set-times` with "now" | File timestamps agree with the guest's clock |
| Task consumer | Refusing a task delivered before its time |
| Push signing | The SigV4 date on every call to the push service. AWS checks it, which makes this the one place an outside party checks the enclave's clock; skew shows up as a refused signature, retried |
| Notification queue | Device enrollment times and retry backoff |

A read that fails mid-run returns the last good reading and logs a warning. A few milliseconds stale is harmless; a zero timestamp means 1970 dates, expired certificates and rejected tokens. A production build always reads PTP, so a missing device stops the boot. The emulator's `testing` build uses the host clock, because QEMU has no PTP device.

### One entropy source

`/dev/nsm` is the device that signs attestation documents. The runtime draws every secret and identifier it hands out from the same device:

| Consumer | What it draws |
|---|---|
| Guest `wasi:random/random` | Every byte, straight from the device (256 bytes per NSM request) |
| Guest `wasi:random/insecure-seed` | A fresh seed per instance, so no two instances share a hash seed |
| Authentication | Registration and challenge IDs, and the 32-byte single-use tokens that admit a request |
| The runtime's own | The wallet key's nonces, sealing nonces, registration handles, pool, task and trace IDs |

If the device fails, `wasi:random` stops the process rather than return predictable bytes. The clock can serve a stale reading because a stale timestamp is still a real one and a caller can notice. Predictable bytes look random to the guest, and a key built from them can never be detected downstream. A production build always reads the NSM. What libraries draw inside themselves comes from the kernel pool: TLS keys and handshakes and the KMS recipient key through `aws-lc-rs`. Inside an enclave the NSM is that pool's only seed, and requiring `/dev/nsm` at boot proves the runtime is in an enclave.

`enclave-runtime --self-check` prints the chosen clock, its skew against `CLOCK_REALTIME` and a sanity check of the entropy source, then exits without touching storage.

### One identity

Before asking for any key, the runtime uses the same NSM to extend PCR16 with the guest's hash and lock the register. The same device then signs every attestation document. Two independent parties check the resulting pair:

```mermaid
flowchart TB
    M["PCR0: runtime image and measured configuration<br/>PCR16: the guest component"]
    M --> K["KMS<br/>releases this release's key to this pair<br/>(enforced by the key policy)"]
    M --> C["Native app<br/>checks the attested /auth answer<br/>before sending its ECDH partial"]
```

PCR0 covers configuration as well as code: the push application and the bucket identities. An app that pins PCR0 has therefore also pinned which push application can wake its devices. A guest's own settings are not image configuration: they travel in the guest file ([`guest-env.py`](deploy/qemu-nitro/guest-env.py) writes them before it is uploaded), so PCR16 measures them with the guest's code and one image serves any deployment. Where a guest can send data is not configuration: a guest reaches the public internet and nothing else, by address, so what it sends is its own code's decision — and that code is PCR16.

## Capabilities beyond WASI

WASI has no interface for waking a person or running something at 3 a.m. The runtime adds small WIT packages for them. **No function takes a tenant ID.** The runtime binds each call to the tenant of the invocation making it, so a guest cannot reach another tenant's devices or tasks.

A guest composes the worlds it needs. From the [example guest](examples/guest-http/wit/app.wit):

```wit
world app {
    include enclave:tasks/background@0.1.0;   // import the queue, export run-task
    import enclave:notify/notify@0.1.0;        // wake the tenant's devices
}
```

A Rust guest depends on [`wit/`](wit/) as a crate, `enclave-wit`, whose bindings are generated from the canonical files, so it keeps no copy ([`guest-signer`](examples/guest-signer/) does this). A guest may also vendor the definitions, as `guest-http` does; `scripts/wit-drift.sh` fails if a copy drifts.

### `enclave:notify` — wake a phone without saying why

```wit
register-device: func(token: string) -> result<_, string>;   // interactive only
forget-device:   func(token: string) -> result<_, string>;   // interactive only
devices:         func() -> result<u32, string>;               // a count, never the tokens
wake:            func(category: string, reference: option<string>) -> result<_, string>;
```

A guest holds no push credential, so the runtime sends on its behalf through AWS End User Messaging Push, signing as the instance's role; the Firebase credential lives on the push application's FCM channel, inside AWS, and no image carries it. **A wake is data-only.** The payload crosses the parent instance, AWS and then Google, so it has no title, no body and no `notification` object, and no setting can add one. It goes as `RawContent`, which reaches the phone as written:

```json
{"data": {"v": "1", "category": "task-done", "ref": "invoice-42"},
 "android": {"priority": "high", "ttl": "3600s"},
 "apns": {"headers": {"apns-push-type": "background", "apns-priority": "5"},
          "payload": {"aps": {"content-available": 1}}}}
```

On waking, the app attests the enclave and fetches the details over its pinned connection, which the parent cannot read.

How notify draws on the rest of the runtime:

- **Credentials.** The runtime signs each call itself (SigV4, dated by the PTP clock) with the instance role's credentials, fetched from the metadata service at an address gvproxy maps for the runtime alone. It sends over an HTTPS client that trusts only the web PKI roots compiled into the image, because the parent answers the enclave's DNS.
- **Authority.** Enrolling or forgetting a device is a standing ability to reach a person, so it takes an interactive, signed call. Raising a wake from background work is the main use: a task finishes and tells its owner to come and look. A wake grants nothing; it uses an enrollment the owner already made.
- **Storage.** Device tokens live in `/runtime/devices` in the encrypted store, outside every tenant's scope. A guest enrolls a token and can only ever get a count back.
- **Delivery** is best effort and bounded. Repeat wakes for one `(tenant, category)` coalesce, and a full queue drops and counts instead of blocking the guest. Transient failures back off, and tokens the service reports gone are pruned. Each tenant can enroll 8 devices; enrolling a ninth evicts the oldest.

A parent that borrows the role can send wake signals through that one application and nothing more. A wake carries no data, and the app's response to any wake is to fetch over the attested channel. Set `ENCLAVE_PUSH_APP_ID` (measured, not secret). See [docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md).

### `enclave:tasks` — work while nobody is connected

```wit
enqueue: func(id: string, payload: list<u8>, run-at: u64, interval-ms: option<u64>) -> result<_, string>;
status:  func(id: string) -> result<string, string>;
cancel:  func(id: string) -> result<_, string>;
forget:  func(id: string) -> result<_, string>;

export run-task: func(task-id: string, payload: list<u8>) -> result<list<u8>, string>;
```

An approved request can schedule work for later, optionally recurring in whole minutes. `run-at` is Unix milliseconds. Tasks are scheduled outside the enclave: DynamoDB records each one where an operator can see it, EventBridge Scheduler fires it, and SQS delivers it to the enclave. The runtime keeps no clock for them. The parent holds the same AWS role, so each task is signed with a key derived from its tenant's key and its payload is sealed to it: the parent can delete or delay a task, but not forge one, read one or run one early. Each run gets a fresh instance, holds the tenant's lock and has a deadline. Failed runs are retried a bounded number of times, and results are kept for `status`. Execution is at least once, so deduplicate by the run ID (`<id>:<generation>:<occurrence>`). Payloads and results are capped at 64 KiB. They run when the guest exports `run-task`; see [docs/BACKGROUND_TASKS.md](docs/BACKGROUND_TASKS.md).

### `enclave:signer` — sign with a wallet key the guest never holds

```wit
wallet-key:  func() -> result<key, string>;                        // public parts only
dealt-share: func(identifier: list<u8>) -> result<list<u8>, string>;
resource signing {
    begin:  static func(messages: list<list<u8>>) -> result<tuple<signing, list<commitment>>, string>;
    finish: func(rounds: list<wallet-round>) -> result<list<list<u8>>, string>;
}
```

Each tenant's wallet key is a 2-of-2 FROST key between the owner's app and the cosigner, made by a DKG across registration's two calls: the app commits in `register/options`, whose answer carries the cosigner's commitment and the share it deals, and `register/verify` completes it ([client integration](docs/CLIENT_INTEGRATION.md#registering)). The runtime signs with the cosigner's share here, one round trip per batch; nothing returns it.

A round has two halves. The guest calls `begin` and relays the enclave's commitments to the app; the app answers with its own half, which the [client library](#a-client-for-native-apps) makes from its share (`signRound`); the guest calls `finish` and gets BIP-340 signatures. Whether a message deserves a signature is the guest's decision, made before it calls `begin`: that check is the guest's policy. [`examples/guest-signer`](examples/guest-signer/) is the smallest guest that does this, about ninety lines, and it signs whatever it is sent.

The cosigner's share is the operator's. Its DKG polynomial is derived from an operator master and a handle the registration mints, and the finished share is sealed under a key from the same master into the tenant's write-once record in the roots bucket. So every release reads it, and nothing is migrated. Neither the master nor the share signs anything alone, and neither opens the tenant's data: both need the app's share too. The master is an SSM SecureString the operator writes once the enclave is up (`ENCLAVE_OPERATOR_MASTER_PARAMETER`), read on the first registration or sign-in. It must never change or be lost, since every cosigner share is sealed under it.

### Who may call what

The runtime marks each invocation as either interactive (a signed request) or background, and allows different calls from each:

| Call | Approved request | `run-task` |
|---|:-:|:-:|
| `tasks.enqueue`, `cancel`, `forget` | ✓ | |
| `tasks.status` | ✓ | ✓ |
| `notify.register-device`, `forget-device` | ✓ | |
| `notify.wake`, `devices` | ✓ | ✓ |
| `signer.*` | ✓ | |
| `wasi:http` to the public internet | ✓ | ✓ |

Background work cannot grant itself more work or devices. It can only use what an approved request already set up.

### Instances are disposable

Every request and `run-task` call gets a fresh instance, dropped when the call ends, so nothing in memory survives from one call to the next. Keep durable state in files and sync or close them before returning, because files an instance left open are released unflushed when it is dropped. A tenant's requests and tasks run one at a time; different tenants run concurrently.

### All together: a background job wakes its owner

```mermaid
sequenceDiagram
    autonumber
    participant App as Phone app
    participant RT as Runtime (enclave)
    participant G as Guest
    participant Push as Push service
    App->>RT: ask for a challenge, with a fresh nonce
    RT-->>App: the challenge, attested with PCR0, PCR16 and the TLS certificate
    App->>RT: a signature by the app's share, and its ECDH partial
    RT-->>App: single-use token from the NSM
    App->>G: approved requests to POST /devices and POST /tasks/report
    G->>RT: notify.register-device, then tasks.enqueue with run-at
    Note over RT: later, when the PTP clock reaches run-at
    RT->>G: run-task in a fresh instance
    G->>RT: write the result, then notify.wake(task-done, report)
    RT->>Push: data-only message, SigV4 signed on PTP time
    Push-->>App: silent wake, through FCM
    App->>RT: sign in, attest, fetch the result
```

The [QEMU harness](deploy/qemu-nitro/run-e2e.sh) runs this flow in an emulated enclave, with a stub in place of the push service that checks the wake carried no content.

## Try it locally

### 1. Run the unit tests

From the repository root, with Rust and its native build prerequisites (a C toolchain, `pkg-config` and OpenSSL headers):

```bash
cargo test --workspace --lib
```

This needs neither Docker nor an AWS account. It covers the clock and entropy adapters, tasks, notifications, authentication, attestation verification and storage. Tests marked ignored need extra fixtures and do not run by default.

### 2. Start the development enclave

The harness boots the real runtime image in QEMU's `nitro-enclave` machine with an emulated NSM. It needs Linux with KVM and vsock, Docker, Nix with flakes, Rust with the `wasm32-wasip2` target, `python3`, `jq`, `curl` and `openssl`:

```bash
rustup target add wasm32-wasip2
sudo modprobe vsock_loopback

docker build -t enclave-qemu-nitro:latest deploy/qemu-nitro   # built from source; ~680 MB
cargo install vhost-device-vsock --version 0.3.0 --locked \
  --root target/qemu-nitro/tools

# Builds the example guest and starts MinIO and a push stub.
deploy/qemu-nitro/dev-enclave.sh --keep-store
```

The first run builds an enclave image and takes a while. The harness prints the URL (default `https://127.0.0.1:8443`), PCR0, PCR16 and the trust-root path, then keeps running.

**The emulator exercises the protocol, not AWS's hardware trust boundary.** It uses a development master key, and it signs attestation documents with a chain it mints at each boot because QEMU's NSM cannot produce AWS-signed ones. It also runs on the host clock. Use it with test data only.

To build on one machine and run on another, `--pack` produces a self-contained bundle and `--prebuilt` runs one; a consumer packs the bundle it needs from a commit it pins. See the [development guide](docs/DEV_ENCLAVE.md).

### 3. Make an authenticated, stateful request

In another terminal, substitute the two measurements the harness printed:

```bash
target/release/wallet-client \
  --url https://127.0.0.1:8443 \
  --state target/qemu-nitro/dev/alice.json \
  --trust-root target/qemu-nitro/dev/trust-root.der \
  --pcr0 <printed-pcr0> --pcr16 <printed-pcr16> \
  get --path /counter
```

The harness registered the wallet in that state file when it started. The client verifies the enclave's attestation and pins its certificate, signs the request with its share, and prints a counter that increases on each run. `enrol` with a different `--state` file registers a different tenant. The software wallet is behind the `testing` feature and is not in the production image.

With `--keep-store`, restarting the harness preserves the store and its tenants. Read the new pins at each boot: the emulator's attestation root changes every time, and a different guest changes PCR16.

### 4. Bring your own component

```bash
deploy/qemu-nitro/dev-enclave.sh \
  --guest path/to/component.wasm \
  --keep-store \
  --guest-env SERVICE_URL=http://192.168.127.254:7070
```

The guest must export `wasi:http/incoming-handler` or `enclave:rpc/service`, and may use the [WIT capabilities](wit/). Background tasks run if the guest exports `run-task`. `192.168.127.254` reaches the development host through gvproxy, on every port but the runtime's own; otherwise a guest reaches the public internet and nothing else.

There is no bare laptop mode: the runtime measures its guest into PCR16 before it boots, and that needs an NSM. Host integration tests use a fake NSM; QEMU provides an emulated one.

## Trust boundaries

```mermaid
flowchart TB
    App["Native app + wallet share"] -->|HTTPS| Parent["Parent instance: gvproxy + vsock"]
    Parent -->|ciphertext only| TLS
    subgraph Enclave["Measured enclave · PCR0 runtime · PCR16 guest"]
        TLS["TLS + attested /auth"] --> Gate["Signature gate"]
        Gate --> Guest["WASI component"]
        Tasks["Task consumer"] --> Guest
        Held["Held connections"] --> Guest
        Dev["PTP clock + NSM"] -.-> Guest
        Guest --> FS["ZFS pool on dm-crypt"]
        Guest --> Notify["Notifier"]
    end
    FS -->|ciphertext blocks over vsock| Disk[("Parent's disk")]
    FS -->|signed anchors| S3[("S3, Object Lock")]
    AWS[("DynamoDB · EventBridge · SQS")] -->|signed tasks| Tasks
    Dev -.->|recipient attestation| KMS["KMS + SSM"]
    Held <-->|attested SSE + POST| Svc["Public services"]
    Notify -->|data-only wake| Push["AWS push → FCM"]
```

The parent provides transport and decides whether the enclave runs. With production key release and client verification configured correctly, it cannot read stored data or the enclave's TLS traffic. It can still stop the service, drop or delay traffic, observe metadata and answer DNS, which is why every outbound connection validates certificates against roots that are part of the measured image.

AWS Nitro attestation, KMS, S3's authenticated responses, Object Lock and the approved runtime and guest are part of the trust model. Attestation identifies code; it does not show the code is safe, so an approved guest is trusted with its tenant's data. Two channels out of the enclave are deliberate:

- **Guest output** is untrusted text. A bounded queue drops rather than blocks, and guest records are separated from runtime events by tracing target, never by message content. Console and CloudWatch logs are operational, not audit evidence: their readers see whatever the guest printed, and the parent can write to the same CloudWatch stream.
- **Egress** carries whatever the guest sends, to any public address. The metadata service, the proxy, this machine and the operator's network are refused by address, after resolution — see [`serve/egress.rs`](runtime/src/serve/egress.rs) — and what the guest sends is its own code's decision, measured by PCR16.

## Measured boot and key release

The image names where the guest lives, an object key in the roots bucket covered by PCR0, and the runtime measures what it actually fetched:

```text
fetch component → SHA-256 → extend PCR16 → lock → re-read the register → this release's KMS key → attach the tenants it kept
```

The runtime refuses to start if PCR16 was already extended or locked, or if the register after extending or locking does not hold what a client computes from the component (`nitro-attest --measure` and the `guest-release` build compute it). A guest-only update changes PCR16 and the client pins without an image rebuild; changes to runtime code or measured configuration change PCR0.

The runtime places an enclave recipient key in an NSM attestation request. Each release has its own key, found under `<ENCLAVE_KMS_KEY_ALIAS>/<sha256(pcr0 ‖ pcr16)>`. The runtime calls `GenerateDataKey` on a release's first boot and `Decrypt` on every boot after, and accepts only `CiphertextForRecipient`, never a plaintext fallback. SSM holds the KMS ciphertext, and the roots bucket holds a pointer that is checked by digest. **The KMS key policy is what enforces release:** it must constrain both `kms:GenerateDataKey` and `kms:Decrypt` on both `kms:RecipientAttestation:PCR0` and `kms:RecipientAttestation:PCR16`. **And nobody may be able to change it.** Before every use the runtime reads the key, its policy and its grants from KMS and refuses unless the key is single-region, generated by KMS and customer managed, has no grants, and its policy allows only reading the key, deleting it, and those two actions pinned to this enclave's PCR0 and PCR16 — no `PutKeyPolicy`, no `CreateGrant`, no wildcards ([`keys/policy.rs`](runtime/src/keys/policy.rs)). Such a policy is set once (it needs `BypassPolicyLockoutSafetyCheck`) and is then permanent: what remains to an attacker is deleting the key, which stops the enclave and reveals nothing. The emulator's `testing` build takes a static key instead, which does not protect it from its operator.

A release's key protects only what that release keeps for itself: the keys of the tenants whose background work it runs. Tenants' data is not under it. Each tenant's pool opens with a key `k` that the owner's share and the cosigner's derive together at sign-in, by threshold ECDH. The app sends its half only to a release whose PCR0 and PCR16 it approves. So a new runtime or guest reads every tenant's data as soon as that tenant's owner signs in to it, and nothing is migrated ([details](docs/STORAGE.md)).

## Verifying the enclave from a client

The enclave generates its TLS key inside the boundary and never releases it. The certificate is self-signed, made at every boot and kept only in memory: a CA could vouch only for a domain, and the attestation vouches for the code. That key is what lets a client check that its own connection ends inside this enclave:

| Header | Contract |
|---|---|
| `x-enclave-nonce` | Required on `register/options` and `request/options`: 8–64 fresh bytes, base64url without padding. Missing or malformed values are rejected before routing. No other call sends it |
| `x-enclave-attestation` | On `register/options` and `request/options`: a COSE-signed NSM document. Stripped from every other response, so a guest cannot supply its own |

The document's `user_data` binds the TLS certificate this connection actually served and the component:

```text
0x12 0x20 || SHA256(TLS leaf DER) || 0x12 0x20 || SHA256(component)
```

A native client verifies the chain against the Nitro root, the document's freshness, its nonce, PCR0, PCR16 and the certificate hash, and pins that certificate, all **before** sending its signature and its ECDH partial, the one thing that opens its data. Each request is approved on its own:

```text
POST /auth/request/options   {group_key, method, path, query}   → single-use challenge, attested
POST /auth/request/verify    {challenge_id, signature, ecdh}    → single-use token (60 s)
<the request>                Authorization: Bearer <token>
```

The signature is BIP-340 by the app's share of the wallet key, over the challenge, the interaction and the hash of the certificate the connection was served, so a signature relayed to any other connection is refused. The approval binds method, path and query, not the body or each message of a stream. Registration is open and creates a new, empty tenant. The runtime refuses to start if a document would exceed 16 KiB; client transports should allow at least 32 KiB for the whole response head, certificate chain included. Browser JavaScript cannot inspect the TLS peer certificate this flow depends on, so clients are native apps. See [client integration](docs/CLIENT_INTEGRATION.md) and the standalone [`nitro-attest`](crates/nitro-attestation/src/bin/nitro-attest.rs) verifier.

## A client for native apps

[`clients/react-native`](clients/react-native/) is that client as a library: `@vtxos/react-native-wallet`, Rust underneath, exported to React Native through UniFFI. It is two parts and nothing else.

| Part | What it does |
|---|---|
| `net` | The attested connection. It checks the enclave's document against the app's pins (the trust root, PCR0 and PCR16) before anything secret is sent, pins the certificate, signs in for each call, and carries a guest's calls as bytes: `Session.call` for one message each way, `Session.stream` for messages both ways |
| `core` | The app's half of the wallet key: made from a passkey's PRF output at registration, kept as a record the app stores, and used by `signRound` for the app's half of a signing round |

It knows nothing of any guest's messages and generates no code from them. An app writes and reads its own guest's messages, and decides what it is willing to sign before it calls `signRound`. Clients are native apps; nothing here is built for a browser.

For an app's own tests the same API runs outside a phone: the `bridge` example speaks it as JSON lines on stdin and stdout, over the runtime in process or over an enclave that is already up, such as the development enclave. See the [package's README](clients/react-native/README.md).

## Storage

Each tenant has its own ZFS pool, on its own 64 MiB region of a disk the parent serves over vsock and cannot read: dm-crypt sits underneath, under a key derived from the tenant's key, which only the owner's share and the cosigner's can derive, together. The guest sees the pool's `data` dataset as `/`, through `wasmtime-wasi`'s filesystem, and nothing above it is reachable. The tenant's device records are on the same pool, outside `data`; its background tasks are in DynamoDB, signed and sealed with its key. Each tenant's wallet key record, with the cosigner's share sealed under the operator master, and which region is whose are in the roots bucket, written once. SQLite runs unmodified in rollback-journal mode ([`guest-sqlite`](examples/guest-sqlite/)).

Rollback is what ZFS alone cannot stop, since the parent holds the disk. So before anything is acknowledged — a response's end, a registration, a task's outcome — the pool is synced and its state anchored. A random value written into the pool is signed, chained and published to an Object-Locked bucket. Attaching a pool imports it as of the newest anchor and refuses one that does not hold its value. The anchor, the boot checks, the parent side and the limits are in [docs/STORAGE.md](docs/STORAGE.md); WASI differences are in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Configuration

Every setting is baked into the image and measured into PCR0, so changing one means building a new image, just as changing a constant would. A production binary therefore reads only what differs between deployments, and `--help` lists exactly these:

| Setting | What it names |
|---|---|
| `ENCLAVE_ROOTS_BUCKET`, `ENCLAVE_BUCKET_PREFIX` | The Object-Locked bucket, and a key prefix so deployments can share one |
| `ENCLAVE_ID` | The filesystem id, which salts every key |
| `ENCLAVE_KMS_KEY_ALIAS`, `ENCLAVE_MASTER_KEY_PARAMETER` | Where each release finds its KMS key and its sealed master secret: `<alias>/<release id>` and `<parameter>/<release id>`, the id being `sha256(pcr0 ‖ pcr16)` |
| `ENCLAVE_OPERATOR_MASTER_PARAMETER` | The SSM SecureString holding the operator master: each wallet key's cosigner half is derived from it and sealed under it. Written by the operator after boot, and never changed. The instance role needs `ssm:GetParameter` on it and `kms:Decrypt` on its key. Setting it turns sign-in on; left unset, every request reaches the guest unauthenticated, with a warning at boot |
| `ENCLAVE_RELEASE` | This runtime release's number, written into every anchor; a pool last written by a higher one is refused |
| `ENCLAVE_ROOT_RETENTION_SECS` | How long anchors and registry records are locked (ten years by default) |
| `ENCLAVE_PUSH_APP_ID` | An AWS End User Messaging Push application, or empty for none |
| `ENCLAVE_GUEST_LOG_GROUP` | A CloudWatch group for guest output, written to its `guest` stream, or empty for the console only |
| `ENCLAVE_TASK_TABLE`, `ENCLAVE_TASK_QUEUE_URL`, `ENCLAVE_TASK_SCHEDULE_GROUP`, `ENCLAVE_TASK_SCHEDULER_ROLE_ARN` | Where background tasks are recorded, delivered and scheduled, and the role the scheduler sends with: all four, or none for no background tasks. `deploy/tofu` creates them |
| `AWS_REGION` | The region |

Everything else is fixed:
- KMS releases the master key.
- Time comes from PTP and randomness from the NSM.
- The network is gvproxy.
- The server listens on :443 with a self-signed certificate made at boot.
- The guest is `guest/guest.wasm` in the roots bucket.
- Background tasks run when the guest exports `run-task`, scheduled where the task settings say.
- A guest's environment is exactly the settings its file carries ([`guest-env.py`](deploy/qemu-nitro/guest-env.py) writes them), measured into PCR16 with its code. Nothing from the runtime's environment reaches it.
- `RUST_LOG` sets the runtime's own logging; `guest=warn` filters guest output.

The emulator's alternatives exist only in the `testing` build, which the emulator image uses: a static master key, a fixed operator master, the host clock, MinIO, stubs for push and logs, and background tasks held in memory. A production binary has none of these settings and none of that code.

| Runtime limit | Default |
|---|---:|
| Unspent interaction token lifetime | 60 s |
| Maximum interaction lifetime | 300 s |
| Request progress timeout | 30 s |
| Tenant locks held / idle timeout | 64 / 900 s |
| Background concurrency / attempt timeout | 8 / 600 s |
| Background tasks per tenant / attempts per occurrence | 64 / 5 |
| Held connections per tenant / message size | 8 / 256 KiB |
| Enrolled devices per tenant | 8 |

## Build, test, and deploy

```bash
cargo build --locked --release -p enclave-runtime
cargo build --locked --release -p nitro-attestation --features cli --bin nitro-attest
scripts/build-guest.sh http          # also grpc and signer; sqlite after scripts/wasi-sdk.sh
cargo build --release -p enclave-runtime --features testing --bin wallet-client   # development only
```

| Command | Coverage |
|---|---|
| `scripts/ci-check.sh` | Formatting, Clippy with warnings denied, workspace library tests, boot-origin tests, and the tests of the two crates shared with the client (`threshold`, `enclave-client`) |
| `scripts/ci-guests.sh` | Builds the guests; tests tasks, dispatch, TLS binding, HTTP/2, gRPC, authentication and logging, and that a guest which signs links against the runtime |
| `scripts/ci-storage.sh` | Real MinIO/S3: retention, remount, corruption, rollback and competing claims (needs Docker) |
| `scripts/ci-e2e.sh` | The stages above, then the full QEMU stack (needs KVM, Docker and Nix) |
| `scripts/wit-drift.sh` | Vendored guest WIT matches [`wit/`](wit/) |
| `scripts/ci-bench.sh` | Criterion storage and instance-cost benchmarks |
| `scripts/ci-mobile-android.sh`, `scripts/ci-mobile-ios.sh` | The client library on each platform: built, its bindings and Turbo Module generated, the TypeScript checked, and the example app built against them |

`cargo test --workspace` alone does not replace these: ignored tests need `--include-ignored`, guests build separately, and some binaries need features. Keep the `testing` feature out of production images.

**Deploying.** Nix builds the measured enclave image; Packer ([`deploy/ami`](deploy/ami/)) builds the parent AMI; OpenTofu ([`deploy/tofu`](deploy/tofu/)) defines buckets, retention, parent resources and logs.

```bash
nix build .#eif                                     # result/enclave.eif, result/pcr.json
nix build .#guest-release --out-link guest-release  # guest.wasm, guest-pcr16.json
nix build .#eif --rebuild                           # rebuild and compare
```

1. Set the bucket identities, filesystem ID, region, KMS key, master-key and operator-master parameters, root retention, guest object key and push application in [`deployment.nix`](deploy/nix/deployment.nix) — or, for a deployment kept in its own repository, in a file of the same shape built with `lib.x86_64-linux.mkEif`.
2. Build the EIF and the guest, and keep PCR0 and PCR16 as release outputs.
3. Provision from `deploy/tofu`. The KMS key, its policy and SSM access are provisioned separately for now; the module's outputs (`role_arn`, `security_group_id`, …) are there for a deployment that adds them.
4. Upload the approved component and bind KMS release to the approved measurements.
5. Start the parent's enclave and gvproxy services. The parent forwards TLS; it never terminates it.
6. From a client pinning the release measurements, verify the boot mode, the trusted devices, key release, the TLS attestation binding, registration and sign-in, and persistence.

Reproducibility, and which inputs remain pinned AWS prebuilt artifacts, are covered in the [Nix build guide](deploy/nix/README.md).

## Limits and remaining work

| Area | Current boundary |
|---|---|
| Nitro validation | Real recipient key release, refusal of substituted measurements, AWS-root attestation, PTP and NSM availability, IMDSv2 networking and CloudWatch delivery need hardware evidence |
| Notifications | The push path is exercised against a stub, not yet against the real service |
| Background tasks | DynamoDB, EventBridge Scheduler and SQS are exercised against LocalEmu and the emulator's in-memory stand-in, not yet against the real services |
| Upgrades | Nothing is migrated: a tenant's data opens with the key its owner's share and the cosigner's derive at sign-in, on any release the app approves. Until the owner's next sign-in, a new release runs none of that tenant's background work |
| Delivery | Tasks, notifications and logs each have their own retry and durability contract; none gives exactly-once side effects |
| Authorization scope | A signature approves one interaction on one route, not every payload byte or stream message. Per-message approval is not built: a guest could check the owner's signature itself, with challenges of its own |
| Recovery | None yet. A wallet key is 2-of-2, so a tenant whose app loses its share is lost. A recovery share would derive the same tenant id and data key |
| Capacity | Each tenant gets a fixed 64 MiB region at registration, the smallest ZFS allows: about 16,000 tenants per TiB, committed whether or not the tenant stays active. Once the disk is full, registration is refused; more room means a bigger disk |
| Single active writer | One enclave imports the pool; no failover |
| Parent disk on Nitro | tofu creates the pool's EBS volume and the AMI serves it with stock nbdkit (`deploy/ami/units/nbdkit.service`); not yet proven on hardware. The emulator serves a disk image with `deploy/qemu-nitro/nbd-stub.py` |
| Anchors | Serial across tenants; each is a pool sync and an S3 round trip |
| Resource isolation | Cache and queue limits exist; per-guest memory quotas and public-service admission control do not |
| Upgrades | A new PCR16 is not a migration. The guest owns its schema and queued-payload evolution |

The [roadmap](docs/ROADMAP.md) records milestone history.

## Repository guide

| Path | Contents |
|---|---|
| [`runtime`](runtime/) | WASI wiring ([`run.rs`](runtime/src/run.rs), [`linker.rs`](runtime/src/linker.rs)), [clock](runtime/src/clock.rs), [entropy](runtime/src/random.rs), measured boot, key sources, TLS and auth, tenancy, [tasks](runtime/src/tasks.rs), [notify](runtime/src/notify/), logging |
| [`wit`](wit/) | Capability contracts: [`notify`](wit/notify/notify.wit), [`tasks`](wit/tasks/tasks.wit), [`telemetry`](wit/telemetry/telemetry.wit), [`signer`](wit/signer/signer.wit), [`rpc`](wit/rpc/rpc.wit), and the [`guest`](wit/guest/guest.wit) world that composes them. Also the `enclave-wit` crate: a Rust guest's bindings to all of it |
| [`crates/nitro-nsm`](crates/nitro-nsm/) | NSM device access: entropy, PCRs, attestation requests |
| [`crates/nitro-attestation`](crates/nitro-attestation/) | Attestation verification and the `nitro-attest` client |
| [`crates/threshold`](crates/threshold/), [`crates/enclave-client`](crates/enclave-client/) | FROST/DKG for the runtime's [wallet key](runtime/src/signer/), and attestation verification for a guest's clients |
| [`runtime/src/store/zfs.rs`](runtime/src/store/zfs.rs), [`nix/kernel-zfs.nix`](nix/kernel-zfs.nix) | Storage: the pool, its disk, the anchor ([docs/STORAGE.md](docs/STORAGE.md)) |
| [`runtime/src/store`](runtime/src/store/) | The roots bucket's S3 backend, the key hierarchy and signing |
| [`examples`](examples/) | Guests: HTTP (tasks and notify), bidirectional gRPC, one that signs with `enclave:signer`, and SQLite |
| [`clients/react-native`](clients/react-native/) | The client library for native apps, `@vtxos/react-native-wallet`: [`net`](clients/react-native/rust/vtxos-client/src/net/) and [`core`](clients/react-native/rust/vtxos-client/src/core/) in Rust, the UniFFI exports, the React Native package and its example app |
| [`deploy/qemu-nitro`](deploy/qemu-nitro/) | Development enclave, emulator self-test, end-to-end harness |
| [`deploy/nix`](deploy/nix/), [`nix`](nix/) | Measured configuration and reproducible EIF assembly |
| [`deploy/ami`](deploy/ami/), [`deploy/tofu`](deploy/tofu/) | Parent AMI and AWS infrastructure |
| [`docs`](docs/) | [Client integration](docs/CLIENT_INTEGRATION.md), [notifications](docs/NOTIFICATIONS.md), [streaming](docs/STREAMING.md), [background tasks](docs/BACKGROUND_TASKS.md), [storage](docs/STORAGE.md), [compatibility](docs/COMPATIBILITY.md), [development enclave](docs/DEV_ENCLAVE.md) |

## License

Workspace packages declare Apache-2.0 in [`Cargo.toml`](Cargo.toml).
