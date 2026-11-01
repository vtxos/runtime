# cosigner

The vtxos cosigner: a `wasm32-wasip2` component that this repository's runtime serves inside a Nitro enclave, one instance per tenant, with no listener of its own. Each `cosigner-v*` release publishes one `cosigner.wasm`, and everything that runs the cosigner downloads that file instead of building it.

| Path | Contents |
|---|---|
| [`guests/cosigner`](./) | The component. [`src/session.rs`](src/session.rs) routes each gRPC stream to its ceremony, and the seal ([`src/store.rs`](src/store.rs)) is the only durable state. [`wit/`](wit/) is its world and the runtime WIT it vendors |
| [`runtime/src/signer`](../../runtime/src/signer/), [`crates/threshold`](../../crates/threshold/) | The wallet key the runtime makes and signs with for this component, and the FROST/DKG cryptography under it |
| [`crates/ark`](../../crates/ark/) | The Ark protocol, and arkd's protos |
| [`crates/enclave-client`](../../crates/enclave-client/) | Attestation verification, for clients |
| [`protocol/protos`](../../protocol/protos/) | The cosigner's wire, which is the source of truth for every client |
| [`guests/fake-host`](../fake-host/) | A small host that runs the shipped component through a wallet's life |

The wallet uses the crates and protos from this repository.

The component holds no FROST secret and does not build `threshold`. The wallet key's DKG runs in the runtime, inside the passkey's registration, and the runtime keeps the cosigner's share and signs with it: the component asks for its rounds over `enclave:signer`, and its seal holds only VTXOs and the delegate. Its MuSig2 tree signing, for the delegate and for boarding, stays here, through `ark`. See [the wallet key](../../docs/CLIENT_INTEGRATION.md#the-wallet-key).

## Build and test

```bash
scripts/ci-cosigner.sh   # the crates' tests (protoc), clippy, the component built by Nix, the fake host
nix build .#cosigner     # the component alone: result/bin/cosigner.wasm
```

`cosigner.wasm` is what the enclave measures into PCR16, so it is built reproducibly. The root [`flake.nix`](../../flake.nix) builds it with everything that reaches its bytes pinned by `flake.lock`: Rust (from `rust-toolchain.toml`), protoc for the build scripts, and the clang that compiles libsecp256k1's C to WebAssembly. The component is a member of the root workspace, so its path dependencies hash by relative path, and the build directory is mapped out of the binary, so a sandboxed Nix and one without a sandbox produce the same file. It builds with the `wasm-release` profile; the runtime's release profile is its own.

`wit/deps` vendors the runtime's capability interfaces (tasks, notify, telemetry, cosign); `scripts/wit-drift.sh` keeps them equal to `wit/`.

## Testing

```bash
scripts/ci-cosigner.sh   # every crate's own tests, on the host, then the component in the fake host
```

[`guests/fake-host/`](../fake-host/) is a small wasmtime host that runs the component a release ships, rather than a native build of its library. It links the component the way the runtime does: WASI, `wasi:http` in both directions, and the runtime's tasks, notify, telemetry and cosign, the last over a `threshold` stand-in for the runtime's wallet key. Each call gets a fresh instance over one tenant directory, so anything that has to survive between calls must go through the cosigner's seal.

The fakes behave like the runtime in the ways that matter:

- **Tasks** are queued, and `run_due` runs them as the runtime's scheduler would. Each run is a fresh instance calling `run-task`.
- **The runtime's rule for background work is enforced.** Only a request may arm a task or enrol a device. A background run may only wake its owner.
- **The ASP** is answered in process. The component's HTTP calls to it never leave the host, and every call is recorded. Any other outgoing request is denied.

[`guests/fake-host/tests/flow.rs`](../fake-host/tests/flow.rs) plays the wallet over the cosigner's gRPC service:

1. DKG, as the runtime runs it at registration, and a device enrolled.
2. Registering, counting and forgetting devices.
3. A signature, checked as BIP-340 under the group key.
4. Renewing the delegate, which arms the cosigner's watch.
5. In the background, the cosigner refreshing the funds on its own. It registers the sealed delegate's intent with the ASP, follows the batch to `Settled`, and wakes its owner.

The tests also cover two failure paths. An ASP that refuses the intent leaves the owner woken with `settle-due`, and the refresh then succeeds on a later run. A background run that asks for anything more than a wake is refused.

## Releases

Pushing a `cosigner-v*` tag publishes `cosigner.wasm`, built by Nix, and `SHA256SUMS`. To check a release, rebuild it from its tag and compare: `nix build 'github:vtxos/runtime/<tag>#cosigner' && sha256sum result/bin/cosigner.wasm`. A tag such as `cosigner-v0.2.0-rc.1` is a prerelease.

The component is published bare. A deployment writes its own settings into it (`guest-env.py`, or `--guest-env` in a dev enclave), and the enclave then measures the configured file into PCR16. The release sha256 therefore identifies the code, not any one deployment's PCR16.

Consumers pin a release by name and sha256:
- the dev enclave image that infra builds for the wallet's e2e
- the production release
