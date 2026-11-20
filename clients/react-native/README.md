# @vtxos/react-native-wallet

A vtxos wallet for React Native, on Android and iOS: the Rust client in
[`clients/mobile`](../mobile) (attested TLS to the enclave runtime, share-signed sign-in, FROST, the
policy guest's ceremonies and the ASP calls they relay), exposed to JavaScript by
[uniffi-bindgen-react-native](https://github.com/jhugman/uniffi-bindgen-react-native) as a Turbo
Module. Every call returns a Promise. The app needs no Rust toolchain: the package ships the built
libraries.

## Usage

```ts
import { Vtxos, prfSalt, encodeRecord, decodeRecord } from '@vtxos/react-native-wallet';

const vtxos = new Vtxos(enclaveUrl, aspUrl, {
  pcr0, // the runtime image, hex
  pcr16, // the policy guest, hex
  maxAgeSecs: 300n,
  // trustRootPem: omitted for AWS Nitro's root
});

// The passkey's PRF output, evaluated at prfSalt(), makes the wallet's key.
const record = await vtxos.register(prfOutput);
await storage.save(encodeRecord(record)); // not secret without the passkey; back it up

const wallet = vtxos.open(decodeRecord(stored), prfOutput);
await wallet.arkAddress();
await wallet.board({ txid, vout, amountSats }, undefined);
await wallet.send(address, 10_000n, { exitAddress, deviceToken });
wallet.close(); // drops the share
```

### Exits

A renewal with an `exitAddress` returns one signed `Exit` per VTXO. Store each one, including
`unroll`: with it, the user can leave even if the ASP has disappeared.

To leave:
1. Put each transaction in `unroll` on chain in order, then `rawTx` once the last of them has
   confirmed and `sequence` has passed.
2. Each one pays no fee and carries a P2A anchor. Broadcast it as a package with a child from the
   app's own on-chain wallet that spends the anchor and pays for both.
3. Do one per block: TRUC allows only one unconfirmed parent.

The provider must accept packages, e.g. Esplora's `POST /txs/package`. The regtest electrs doesn't
have that endpoint; on regtest, use bitcoind's `submitpackage`.

An exit holds until its VTXO is spent or refreshed, or its batch expires; a newer one replaces it.

Errors are `VtxosError`s: check `VtxosError.Attestation.instanceOf(e)`, and so on for `Pinning`,
`Auth`, `Enclave`, `Asp`, `WrongPasskey`, `Protocol` and `Transport`.

## Building

`android/`, `ios/`, `cpp/`, `src/` and the podspec are generated from `clients/mobile/vtxos-uniffi`
and not committed. Generate them, with the libraries, for one platform or both:

```sh
yarn                # Node from .nvmrc; Yarn through corepack
yarn ubrn:android   # arm64-v8a and x86_64, with cargo-ndk and NDK 27 (ANDROID_NDK_HOME)
yarn ubrn:ios       # devices and the simulator, into an xcframework; macOS only
yarn typecheck
```

Both need `protoc` and the Rust targets: `aarch64-linux-android` and `x86_64-linux-android`, or
`aarch64-apple-ios` and `aarch64-apple-ios-sim`. Android is 64-bit only, so an app using the package
must build just `arm64-v8a` and `x86_64` (`reactNativeArchitectures` in its `gradle.properties`).
[`scripts/ci-mobile-android.sh`](../../scripts/ci-mobile-android.sh) and
[`scripts/ci-mobile-ios.sh`](../../scripts/ci-mobile-ios.sh) do exactly what CI does.

## The example app

The example talks to the runtime running in process on this machine, serving the policy guest, and
to a regtest arkd on `127.0.0.1:7070`:

```sh
nix build .#policy
(cd clients/mobile && POLICY_WASM=<path to policy.wasm> cargo run -p vtxos-uniffi --example dev_enclave)
```

It prints an `adb reverse` command, which lets an emulator reach both, and a line of settings
(URLs and pins). Then:

```sh
yarn example android
```

Paste the settings line into the app and register. To board, pay the boarding address on regtest,
mine a block, and enter the output as `txid:vout:sats`.
