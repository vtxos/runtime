# policy

The vtxos policy guest: a `wasm32-wasip2` component that this repository's runtime serves inside a Nitro enclave, one instance per tenant, with no listener of its own. Each `policy-v*` release publishes one `policy.wasm`, and everything that runs the guest downloads that file instead of building it. (Releases before the rename were tagged `cosigner-v*` and shipped `cosigner.wasm`.)

| Path | Contents |
|---|---|
| [`guests/policy`](./) | The component. It exports `enclave:rpc/service`: the runtime ends gRPC and hands each call over as messages. [`src/session.rs`](src/session.rs) routes each call to its ceremony, and the seal ([`src/store.rs`](src/store.rs)) is the only durable state |
| [`wit/`](../../wit/) | Its world (`enclave:guest/guest`) and the runtime's interfaces, as the `enclave-wit` crate it depends on. It keeps no WIT of its own |
| [`runtime/src/signer`](../../runtime/src/signer/), [`crates/threshold`](../../crates/threshold/) | The wallet key the runtime makes and signs with for this component, and the FROST/DKG cryptography under it |
| [`crates/ark`](../../crates/ark/) | The Ark sessions this component drives, built on Arkade's `ark-core` (which builds every transaction and computes every sighash), and arkd's protos |
| [`crates/enclave-client`](../../crates/enclave-client/) | Attestation verification, for clients |
| [`protocol/protos`](../../protocol/protos/) | The guest's wire (still `cosigner.v1` / `Policy`), which is the source of truth for every client |
| [`guests/fake-host`](../fake-host/) | A small host that runs the shipped component through a wallet's life |

The wallet uses the crates and protos from this repository.

The component holds no FROST secret and does not build `threshold`. The wallet key's DKG runs in the runtime, inside the passkey's registration, and the runtime keeps the policy's share and signs with it: the component asks for its rounds over `enclave:signer`, and its seal holds only VTXOs and the delegate. Its MuSig2 tree signing, for the delegate and for boarding, stays here, through `ark`. See [the wallet key](../../docs/CLIENT_INTEGRATION.md#the-wallet-key).

## Build and test

```bash
nix develop .#policy                 # Rust, protoc, the wasm clang, and fake-host-run
cd guests/policy && cargo test       # its tests, as wasm, inside the fake host
nix build .#policy                   # the component alone: result/bin/policy.wasm
scripts/ci-policy.sh                 # all of it, as CI runs it
```

`policy.wasm` is what the enclave measures into PCR16, so it is built reproducibly. The root [`flake.nix`](../../flake.nix) builds it with everything that reaches its bytes pinned by `flake.lock`: Rust (from `rust-toolchain.toml`), protoc for the build scripts, and the clang that compiles libsecp256k1's C to WebAssembly. The component is a member of the root workspace, so its path dependencies hash by relative path, and the build directory is mapped out of the binary, so a sandboxed Nix and one without a sandbox produce the same file. It builds with the `wasm-release` profile; the runtime's release profile is its own.

The runtime's interfaces come from [`enclave-wit`](../../wit/), a crate whose directory is the runtime's own `wit/`: its bindings are generated from those files, so there is nothing here to keep in step. The component calls them directly; there is no trait standing in for the runtime.

## Testing

The tests are wasm too. [`.cargo/config.toml`](.cargo/config.toml) builds them for `wasm32-wasip2` and hands each test binary to `fake-host-run`, which runs it against the fake host's runtime: the code under test calls `enclave:signer`, `enclave:tasks` and `enclave:notify` exactly as a release does. A test sets its runtime up and reads it back through `enclave:fake-host/control` (`tests/common`'s `Recorder`): the wallet key it dealt, and what was enqueued, cancelled and woken. One fake host runs a whole test binary, so each test starts it over.

[`guests/fake-host/`](../fake-host/) is a small wasmtime host that also runs the component a release ships, rather than a native build of its library. It links the component the way the runtime does: WASI, outgoing `wasi:http`, and the runtime's tasks, notify, telemetry and signer, the last over a `threshold` stand-in for the runtime's wallet key. It calls the component's `enclave:rpc/service` export as the runtime does, with real streams. Each call gets a fresh instance over one tenant directory, so anything that has to survive between calls must go through the policy's seal.

The fakes behave like the runtime in the ways that matter:

- **Tasks** are queued, and `run_due` runs them as the runtime's scheduler would. Each run is a fresh instance calling `run-task`.
- **The runtime's rule for background work is enforced.** Only a request may arm a task or enrol a device. A background run may only wake its owner.
- **The ASP** is answered in process. The component's HTTP calls to it never leave the host, and every call is recorded. Any other outgoing request is denied.

[`guests/fake-host/tests/flow.rs`](../fake-host/tests/flow.rs) plays the wallet over the policy's service:

1. DKG, as the runtime runs it at registration, and a device enrolled.
2. Registering, counting and forgetting devices.
3. A signature, checked as BIP-340 under the group key.
4. Renewing the delegate, which arms the policy's watch.
5. In the background, the policy refreshing the funds on its own. It registers the sealed delegate's intent with the ASP, follows the batch to `Settled`, and wakes its owner.

The tests also cover two failure paths. An ASP that refuses the intent leaves the owner woken with `settle-due`, and the refresh then succeeds on a later run. A background run that asks for anything more than a wake is refused.

## Releases

Pushing a `policy-v*` tag publishes `policy.wasm`, built by Nix, and `SHA256SUMS`. To check a release, rebuild it from its tag and compare: `nix build 'github:vtxos/runtime/<tag>#policy' && sha256sum result/bin/policy.wasm`. A tag such as `policy-v0.2.0-rc.1` is a prerelease.

The component is published bare. A deployment writes its own settings into it (`guest-env.py`, or `--guest-env` in a dev enclave), and the enclave then measures the configured file into PCR16. The release sha256 therefore identifies the code, not any one deployment's PCR16.

Consumers pin a release by name and sha256:
- the dev enclave image that infra builds for the wallet's e2e
- the production release
