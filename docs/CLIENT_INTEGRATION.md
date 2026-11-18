# Integrating a client against this runtime

For a team with an existing Nitro client, pointing an app at this enclave for
the first time.

If you have been talking to a **nitriding** enclave, the short version is: the
endpoints, the `user_data` layout and the trust model are all different. Every
request is also approved with a signature by the app's share of a wallet key,
which nitriding has no equivalent of. This is not a base-URL change. It is
maybe a day of client work, and most of it is in one file.

You can have the enclave running locally, serving your own guest, in about ten
minutes — see [Run it](#run-it). You develop against the same verification code
path you will run in production.

## What is different, in one table

|  | nitriding | this runtime |
|---|---|---|
| get the document | `GET /enclave/attestation?nonce=` | `x-enclave-attestation` header on `register/options` and `request/options` |
| enclave info | `GET /v1/enclave-info` | none; everything is in the document |
| `user_data` | `"sha256:" + tlsKeyHash + ";" + "sha256:" + appKeyHash` | 68 bytes: `0x1220 ‖ sha256(tls_cert_der) ‖ 0x1220 ‖ sha256(guest_component)` |
| pinned | PCR0 | PCR0 **and** PCR16 |
| per-request auth | none | a BIP-340 signature by the app's share of the wallet key, bound to that exact method and path |
| tenancy | yours to build | one tenant per wallet key, enforced by the runtime |

The last two rows change the app, not just the crate.

## Run it

You need Linux with KVM, Docker and Nix. Once per boot:

```bash
sudo modprobe vsock_loopback
```

Once ever:

```bash
docker build -t enclave-qemu-nitro:latest deploy/qemu-nitro
cargo install vhost-device-vsock --root target/qemu-nitro/tools
```

Then, with your component:

```bash
cargo build --release --target wasm32-wasip2   # in your guest's crate
deploy/qemu-nitro/dev-enclave.sh --guest target/wasm32-wasip2/release/policy.wasm
```

The script:

1. builds the enclave image;
2. starts a store and a disk;
3. boots the enclave under QEMU's `nitro-enclave` machine;
4. waits for the enclave to fetch and measure your component and serve HTTPS;
5. prints the three values a client pins, and stays up.

Ctrl-C stops everything it started.

There is nothing to configure. The enclave fetches the guest from the store at
boot and measures it into PCR16 before it can obtain a key. So a new build means
a new PCR16 and a restart. See [dev-enclave](DEV_ENCLAVE.md) for the details,
the options, and what is and is not real about it.

## The protocol

Only `/auth/*` answers without a token. Every other request reaches the guest,
and only with a fresh approval.

The four `/auth/*` endpoints take and return JSON. Every request body rejects
unknown fields: an extra field gets a 400 rather than being ignored.

Encodings:
- Binary values are hex, except the two single-use ids, which are unpadded
  base64url.
- DKG packages are JSON strings in `crates/threshold`'s format, which is the
  shape the Dart FROST library's `Round1Package` and `Round2Package` read and
  write.

### The wallet key

Registration makes the wallet key, and with it the tenant key.

- **The wallet key `X`.** A 2-of-2 FROST key between the app and the runtime,
  made by a Pedersen DKG during registration.
  - The app holds the share `x_w`, with verifying share `Y_w` and identifier
    `id_w`.
  - The runtime holds `x_c`, with `Y_c` and `id_c`.
  - The runtime signs with its half on the guest's behalf. No guest holds a
    FROST secret.
- **The tenant key `k`.** It opens the tenant's data, and neither side holds it
  alone. Each sign-in derives it again by threshold ECDH between the two shares
  ([below](#the-tenant-key)), and every qualifying pair of shares gives the same
  `k`.

The tenant id is `sha256("aegira/tenant/v1" ‖ X)[..16]`. It comes from the
group key, not from either share, so it survives a change of shares. For
example, `X = 7·G` gives `ecf80fb854cd261687d9881a8b6498ec`. The guest sees this
id in `x-enclave-tenant`.

The app's DKG polynomial is the app's own choice. It can be random, or derived
from something the app already has, such as a passkey's PRF output. The runtime
never sees it.

The app has to keep:
- its key package: `x_w`, `id_w`, `Y_w` and `X`;
- the runtime's `id_c` and `Y_c`, to check the runtime's ECDH proofs.

There is no recovery yet. If the app loses `x_w`, the tenant is lost. A recovery
share is planned: it would derive the same `k` and keep the same tenant id.

### Registering

Registration is **open**: any app may register a wallet key, and each key gets
its own tenant with its own isolated filesystem. There is no invitation, no
enrolment token and no operator step.

Registration is two calls, which together carry the whole DKG. The app commits
first.

```
1.  POST /auth/register/options
    {"dkg": {"round1_package": "<the app's round one: commitment and proof of knowledge>"}}
      → 200 {"registration_id": "<base64url, 16 bytes>",
             "dkg": {"round1_package": "<the runtime's round one>",
                     "round2_package": "<f_c(id_w): the share the runtime deals the app>"}}
      + header x-enclave-attestation: <base64 COSE_Sign1>

2.  verify that document against this connection (Step 2, below),
    and pin the certificate the connection was served

3.  finish the DKG: part 2 deals f_w(id_c) to the runtime, and part 3 gives the key package

4.  POST /auth/register/verify                     — on the pinned certificate only
    {"registration_id": "...",
     "dkg": {"round2_package": "<f_w(id_c): the share the app deals the runtime>"},
     "signature": "<hex, 64 bytes: BIP-340 by x_w over the register message>",
     "ecdh": {"share": "...", "a": "...", "b": "...", "s": "..."}}
      → 200 {"tenant_id": "<hex, 16 bytes>",
             "group_key": "<X, compressed, hex>",
             "ecdh": {<the runtime's partial>}}
```

**What the app sends, and when:**
- The app's round one is public, so nothing secret goes out before the document
  has been checked.
- `register/verify` carries a dealt share and the ECDH partial, which together
  with the runtime's share give the tenant key. So it goes only to the
  certificate that the step 2 document bound.

**Checking the runtime's answer.** `dkg_part2` and `dkg_part3` check most of
this:
- The runtime's round one has two commitments, and its proof of knowledge
  verifies.
- `id_c` is derived from that round one, as the app's own id is:
  `SHA-256(compressed a0·G) mod n`.
- The dealt share lies on the runtime's commitment.

After part 3, `X` has an even y: `dkg_part3` negates every share when it does
not. The app signs, and runs ECDH, with the normalised `x_w`. The answer's
`group_key` must equal the app's own `X`.

**What the runtime keeps.** `register/verify` keeps nothing unless the dealt
share, the signature and the ECDH proof all verify. When they do, the same call:
- writes the tenant's record;
- claims the tenant's disk region;
- creates the tenant's data under `k`.

An abandoned or refused registration leaves nothing behind.

**`registration_id`** is good for one `register/verify`, within five minutes.
That call consumes it whether or not it succeeds. After a failure, start again
from `register/options`; reusing the id gets a 403.

**The runtime's polynomial is derived, not random.** Each coefficient is
HKDF-SHA256 with the operator master as input key material and
`"aegira/cosigner-dkg/v1"` as salt, expanded to 64 bytes and reduced mod n:
- `a0_c` uses info `handle ‖ 0x00`;
- `a1_c` uses info `handle ‖ id_w ‖ 0x01`.

`handle` is 16 fresh NSM bytes that `register/options` mints. The polynomial is
made inside the attested enclave after the app has committed, so it cannot be
steered toward the app's key. The runtime stores only the handle.

**Before the operator master is provisioned**, `register/options` answers 503.

### Signing in

Each request takes three calls, because the approval is bound to the request
rather than to a session. It has the same shape as registration: the options
call identifies the enclave, and nothing secret goes out until its document has
been checked.

```
1.  POST /auth/request/options
    {"group_key": "<X, hex>", "method": "POST", "path": "/sign", "query": null}
      → 200 {"challenge_id": "<base64url, 16 bytes>"}
      + header x-enclave-attestation: <base64 COSE_Sign1>

2.  verify that document against this connection (Step 2, below),
    and pin the certificate the connection was served

3.  POST /auth/request/verify                      — on the pinned certificate only
    {"challenge_id": "...",
     "signature": "<hex, 64 bytes: BIP-340 by x_w over the request message>",
     "ecdh": {<the app's partial>}}
      → 200 {"token": "...", "expires_in_secs": 60, "ecdh": {<the runtime's partial>}}

4.  the real request, with  Authorization: Bearer <token>  — on the pinned certificate
```

**The challenge** is issued for the method, path and query in the request, and
for the tenant that `group_key` names. A token moved to another route is refused
— enforced, not advisory.
- The runtime issues a challenge for any well-formed key, with a document all
  the same, so asking for one says nothing about which keys are tenants.
- A challenge is single use and lasts 60 seconds.

**Every sign-in carries the partial.** It is what opens the tenant's data when
that is closed, after a restart for instance. The app cannot know whether it
is, and the runtime does not say: anyone may ask for a challenge for any key. A
`request/verify` without `ecdh` is malformed, and gets a 400.

**The signature names the certificate.** The signed message includes the hash
of the certificate the connection was served, so a signature relayed to any
other connection is refused.

**Every refusal of who is asking is the same 401.** Its body is the one sentence
"a fresh signature bound to this request is required", and it carries no
document. That covers:
- an unknown or revoked tenant;
- a wrong signature;
- a signature naming another certificate;
- a used or expired challenge;
- a bad ECDH proof.

The enclave's log records which check failed. The answer does not say.

**Other answers:**
- 503 `try again`, when too many challenges or registrations are outstanding.
- 503, when the operator master is not provisioned.
- 409 `this tenant was last served by a newer release`.

**Tokens:**
- A token is **single use** and expires in 60 seconds. That bounds the time to
  *start* an interaction, not how long one may run: a long stream approved once
  keeps going.
- The runtime strips auth headers before the guest sees the request. A guest can
  neither read a client's token nor forge one.

### What the app signs

```
m = SHA-256("aegira/approval/v1" ‖ for each field: u32-be length ‖ bytes)

register:  "register", registration_id, X, id_w, certificate
request:   "request",  challenge_id,    X, id_w, certificate, method, path, query
```

The fields:
- `registration_id`, `challenge_id`: the 16 decoded bytes.
- `X`: compressed, 33 bytes.
- `id_w`: the app's FROST identifier, 32 bytes, big-endian.
- `certificate`: SHA-256 of the DER of the certificate this TLS connection was
  served. This is the value a document's `user_data` binds.
- `method`, `path`, `query`: as sent to `request/options`. A query is `0x00`
  when there is none and `0x01 ‖ query` when there is one, so a bare `?` is a
  different request from no query.

The signature is BIP-340 over the 32 bytes of `m`, under the x-only key of
`Y_w`. As BIP-340 requires, the signer negates `x_w` if `Y_w` has an odd y. The
same `m` is the transcript of the ECDH proof that goes with the signature.

Test vectors, with `X` = `02` × 33, `id_w` = `01` × 32 and a certificate hash of
32 zero bytes:

| message | inputs | `m` |
|---|---|---|
| register | `registration_id` = `07` × 16 | `8df647a0fa17dbe593f73e94b149eb02d11b896c7e68c53c9e5458a6dd1a6325` |
| request | `challenge_id` = `09` × 16, `POST /sign`, no query | `8478b9e19a9acda3141924f43138ad7e96d6250eadffc5b8067d9b0957a846d4` |

### The tenant key

```
R   = hash_to_curve(compressed X)    RFC 9380, suite secp256k1_XMD:SHA-256_SSWU_RO_,
                                      DST "aegira-v1-secp256k1_XMD:SHA-256_SSWU_RO_"
D_w = x_w·R                           the app's partial, with a Chaum-Pedersen proof:
  A = n·G,  B = n·R                     n fresh for every proof
  c = H("aegira/ecdh/dleq/v1", G ‖ Y_w ‖ R ‖ D_w ‖ A ‖ B ‖ m)
  s = n + c·x_w
Z   = λ_w·D_w + λ_c·D_c               Lagrange at zero over {id_w, id_c}
k   = HKDF-SHA256(ikm = compressed Z, no salt, info = "aegira-v1-session-key" ‖ compressed X)
```

`H` is a BIP-340 tagged hash, reduced mod n, over the compressed points followed
by `m`.

**On the wire**, a partial is `{"share": D, "a": A, "b": B, "s": s}`:
- three compressed points, 33 bytes each, with a prefix of `02` or `03` only;
- a canonical scalar `s`, 32 bytes;
- all hex.

An invalid or identity point, or an `s` that is not below n, gets a 400.

**Check the runtime's partial before using it**: `s·G == A + c·Y_c` and
`s·R == B + c·D_c`. If either check fails, abort. Never fall back to an
unchecked `D`.

**`n` must be fresh for every proof.** The same `n` used for two transcripts
gives away `x_w`. `crates/threshold` hedges it as
`n = H("aegira/ecdh/nonce/v1", x_w ‖ D_w ‖ m ‖ 32 random bytes)`, so even a weak
RNG gives a different `n` for a different `m`.

**`λ` are general Lagrange coefficients**, because the identifiers are hashes,
not 1 and 2.

**Zeroize** `n`, `Z` and `k` once used. Don't store `k`; derive it again. The
runtime's partial comes back in every answer to a partial, so the app can derive
`k` itself whenever it needs it.

**Sending the partial is how the app approves a release.** Every release of the
enclave derives `k` from the partial the app sends it, and has no other way to.
A release the app does not approve is never sent the partial and opens none of
the tenant's data — a substituted guest, say, or a runtime nobody built. So send
the partial only on a certificate whose document passed Step 2, with PCR0 and
PCR16 matching a release the app approves.

A release keeps `k` for the tenant's background work only while it remains that
release. After a new release, background work waits until the owner's next
sign-in sends the partial. That includes the cosigner's VTXO renewal.

**Test vector.** `f(z) = 7 + 3z` (so `X = 7·G`), identifiers 1 and 2,
transcript `"aegira-kat"`, and every random byte `0x42`:

| | |
|---|---|
| `R` | `0251cc89eb233cc5484ff14079783c9233cc1b85a0ef144fee8f29f0c814caea14` |
| `D_1` | `03b1e4e988c0c04c6ae50e4b902e93f3c7a4d459762e91a3230828279fc9b41aa2` |
| `A_1` | `038e0e5d08c1e8e798d63acebf9bfacfbe90d43922be4636a6fde90e65ecc5822d` |
| `B_1` | `038b25cab42a1c8eeeb3a16bd087a6d28850e26bb34d040f06ef174b29e1e8efde` |
| `s_1` | `99b106c9e89440265ce98e4bade3eefb978085b0bbb69235593ed8bafce582a5` |
| `k` | `c607455d21237800381d7a93b72a0eab6fa842abf15b8cd85688eb5c2460ce74` |

[`crates/threshold/src/ecdh.rs`](../crates/threshold/src/ecdh.rs) implements
this. [`tests/ecdh_test.rs`](../crates/threshold/tests/ecdh_test.rs) holds
these vectors, plus RFC 9380's own hash-to-curve vectors (J.8.1).

### Step 2, in full

This is the part worth implementing carefully: the whole design rests on it.
Given the document bytes from `x-enclave-attestation`:

1. **Signature and chain.** COSE_Sign1, ES384. `cabundle` is ordered root
   first; the chain to check is `cabundle` in order, then `certificate`. Every
   certificate except the leaf must be a CA, each must be validly issued by the
   one before it, and each must be inside its validity window.
2. **Root.** The presented root must equal the one you pinned. Do not accept
   "some root" — see [Dev and production](#dev-and-production).
3. **PCR0**, against the value the image build published.
4. **PCR16**, against the value your component measures to. `nitro-attest
   --measure <component>.wasm` prints it, and the runtime computes it the same
   way.
5. **`user_data` binds this connection.** 68 bytes, two sha2-256 multihashes:

   ```
   0x12 0x20 ‖ sha256(tls_certificate_der) ‖ 0x12 0x20 ‖ sha256(guest_component)
   ```

   The first must equal sha256 of the DER of the certificate **this TLS
   connection was served**. That is what ties the document to the channel you
   are on. Without it, a verified document proves an enclave exists somewhere,
   not that you are talking to it.
6. **Nonce** — the one you sent, echoed back. It is not optional: both options
   calls must carry `x-enclave-nonce` (unpadded base64url, 8–64 bytes). One
   without it is refused with a 400 before routing, with no document. No other
   call sends it, because no other answer is attested.
7. **Age.** The document carries the enclave's own timestamp. Reject an old one.

Why both registers, since it is the usual question:
- PCR0 is measured by the hypervisor from the image, so nothing inside the
  enclave can choose it. But the image does not contain the guest.
- PCR16 is the guest, measured and locked by the runtime before it could obtain
  a key. But the *runtime* writes it, so an enclave running somebody else's
  runtime could claim your guest's value.

PCR0 says the runtime that wrote PCR16 is yours; PCR16 says which application it
loaded. Neither substitutes for the other.

**The certificate is self-signed**, and that is deliberate. The enclave makes it
at every boot, with a key that never leaves the enclave. No CA signs it, because
a CA would add nothing the document does not already say better. So the TLS
layer must accept the certificate the server presents without CA or name checks,
keep its DER, and trust it only once a document binds its hash.

The verify calls' answers and guest responses deliberately carry no document.
By then you have pinned the certificate, and TLS proves the peer still holds its
key. So **refuse any connection that serves a different certificate**, and
attest again before using it. Every restart serves a new certificate, which
looks exactly like an interception. A fresh document — the one on the next
challenge — is what tells them apart.

### What the guest sees

Your component receives an ordinary `wasi:http` request with
`x-enclave-tenant` set to the caller's tenant, and a filesystem rooted at that
tenant's own directory. The runtime, not the guest, refuses path traversal out
of it. You do not have to implement tenant separation; you only have to not
work around it.

### A response counts when it ends

The runtime makes a request's writes durable — synced and anchored, see
[STORAGE.md](STORAGE.md) — before the response *ends*. The end is the last chunk
of a chunked body, HTTP/2's end of stream, or gRPC's status trailers. A streamed
body streams as the guest writes it; only its end waits. A body with a
`Content-Length` is held whole.

So treat a response as an acknowledgement only once it is complete. One that
stops short may describe writes that the next boot rolls back: the connection
closed before the terminating chunk, or with fewer bytes than its
`Content-Length`. Standard HTTP clients already fail such a response, and
[`wallet-client`](../runtime/src/bin/wallet-client.rs) does too.

## What changes in an existing verifier

A crate shaped like a pure-verification library — bytes in, no HTTP, no async —
is exactly the right shape. The changes are:

1. **Source of the document**: the `x-enclave-attestation` response header on
   `register/options` and `request/options`, not a GET endpoint.
2. **Add a trust-root parameter.** Default to the AWS Nitro root, and allow an
   override. This is the only thing that differs between dev and production.
3. **Add PCR16** to what is pinned, alongside PCR0.
4. **Replace the `user_data` parser** with the multihash layout above, and
   actually compare against the served certificate. That means the HTTP layer
   has to hand the peer certificate down to the verifier, and to the code that
   signs, because the signed message names it too.
5. **Accept a self-signed certificate**, and pin it by its hash once a document
   binds it.
6. **App side**:
   - the DKG across the two registration calls;
   - the options → document check → verify → token sequence;
   - the ECDH partial, sent only on a pinned certificate;
   - keeping the key package.

### One decision to make

This repo's [`nitro-attestation`](../crates/nitro-attestation) crate already
does all of Step 2. By design it has no dependency on any enclave-side code, and it is what the runtime and every end-to-end leg are tested against.
Depending on it directly means one verifier instead of two implementations that
have to agree.

The catch is real, though: it verifies with `aws-lc-rs`, which needs a C
toolchain and CMake to cross-compile. A pure-Rust `p384`/`x509` stack is
friendlier for iOS and Android builds. So this is a trade-off — one maintained
verifier against an easier mobile build — and not an obvious win either way.

If you keep your own, the two things most worth copying are the chain order
(`cabundle` root-first, then the leaf) and the rule that a non-pinned root is
reported distinctly rather than accepted quietly.

## Dev and production

The difference is one value: the trust root.

|  | dev enclave | production |
|---|---|---|
| trust root | the file `dev-enclave.sh` prints | omit — the AWS Nitro root |
| PCR0 | printed at startup | from the release image build |
| PCR16 | printed at startup | from your component's release build |
| TLS certificate | self-signed, new at every boot | the same |

Everything else — the endpoints, the verification steps, the failure modes — is
identical. That is the point: you are not developing against a relaxed path and
meeting the real one in production.

**Do not set an "allow untrusted root" flag to make dev work.** A verifier that
accepts whatever root a document arrived with is checking nothing, and it will
pass in production too. Pin the dev root as a root; the code path is then the
same one production uses.

## What the local enclave does not prove

Worth being plain about, because it is easy to assume otherwise.

QEMU's emulated NSM does not sign anything. Its source says *"we don't actually
sign the data, so we use -1 as the 'alg' value"*, and -1 is not a COSE algorithm
identifier. So the emulator image mints a certificate chain at boot and re-signs
the documents the device produced, contents untouched. Your client then runs its
whole verification path against something it can accept.

But the key is inside an image that whoever runs it controls. A verified
document means *"this image said so"* locally, where on hardware it means *"a
Nitro enclave with this measurement said so"*. That is why the root changes at
every boot: there is deliberately nothing to hardcode into an app.

KMS is not exercised either. It will not release a key against a document it
cannot trace to a Nitro root, so the local image uses a static master key. On
hardware, a key policy pinning PCR0 and PCR16 stops a substituted guest from
reading anything. Locally, a substituted guest boots and serves, and only the
client's PCR16 check refuses it.

Neither limitation affects the client code you write. Both are reasons to run
against real hardware before you ship.

## Settings the local enclave uses

| | |
|---|---|
| URL | `https://127.0.0.1:8443` (override with `--port`) |
| certificate | self-signed for `localhost`, new at every boot; pinned by its hash, its name never checked |
| registration | the two calls within 5 minutes; the id is single use |
| challenge TTL | 60s, single use |
| token TTL | 60s, single use |

## Reference client

[`runtime/src/bin/wallet-client.rs`](../runtime/src/bin/wallet-client.rs)
implements all of the above, including a software wallet. When something here
disagrees with it, the client is the executable answer. The end-to-end harness
drives it, so it is known to work against a running enclave.

```bash
wallet-client --url https://127.0.0.1:8443 --state alice.json \
    --trust-root <printed> --pcr0 <printed> --pcr16 <printed> \
    enrol
wallet-client --url https://127.0.0.1:8443 --state alice.json \
    --trust-root <printed> --pcr0 <printed> --pcr16 <printed> \
    get --path /whatever-your-guest-serves
```

`--dump-proof <dir>` writes the three things a verifier cannot recover
afterwards: the document, the certificate that connection was served, and the
nonce. That is the fastest way to test a verifier offline:

```bash
nitro-attest --document <dir>/document.b64 --peer-certificate <dir>/certificate.der \
    --nonce "$(cat <dir>/nonce.hex)" --trust-root <printed> --pcr0 <printed> --pcr16 <printed>
```
