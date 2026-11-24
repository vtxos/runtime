# @vtxos/react-native-wallet

The phone's side of a vtxos enclave, for React Native on Android and iOS. It is two things:

- **The key.** A 2-of-2 between the phone and the enclave. The phone's half is made from a
  passkey, never stored, and signs its half of a round inside the library.
- **Calls.** An attested connection to the enclave runtime, a sign-in for each call, and the call
  itself, to any method the enclave serves, as bytes.

It knows nothing of what a call's messages mean. Those belong to whoever wrote the policy the
enclave runs, and so to the app: the app writes and reads them itself.

It is the Rust client in [`rust/`](rust), exposed to JavaScript by
[uniffi-bindgen-react-native](https://github.com/jhugman/uniffi-bindgen-react-native) as a Turbo
Module. The app needs no Rust toolchain: the package ships the built libraries.

## Usage

```ts
import { Enclave, prfSalt, encodeRecord, decodeRecord } from '@vtxos/react-native-wallet';

const enclave = new Enclave(enclaveUrl, {
  pcr0, // the runtime image, hex
  pcr16, // the policy the enclave runs, hex
  maxAgeSecs: 300n,
  // trustRootPem: omitted for AWS Nitro's root
});

// The passkey's PRF output, evaluated at prfSalt(), makes the key.
const record = await enclave.register(prfOutput);
await storage.save(encodeRecord(record)); // a cache: registering again with the passkey returns it

const session = enclave.open(decodeRecord(stored), prfOutput);

// One message each way.
const reply = await session.call('/acme.v1.Limits/Set', request);

// Messages both ways.
const stream = await session.stream('/acme.v1.Vault/Approve');
await stream.send(first);
const answer = await stream.next(); // undefined once the enclave ends the call
stream.finish(); // nothing more from this side

// The phone's half of a signature, when the policy opens a round: its commitments in, and what
// goes back to it. The share never leaves the library.
const rounds = session.signRound(messages, commitments);

session.close(); // drops the share
```

- Each call makes the whole trip: the attested connection, a sign-in for exactly that method, and
  the call with the token the sign-in returned. An enclave that is not the one pinned is refused
  before anything secret goes out.
- A call the enclave ends with an error throws `VtxosError.Status` with gRPC's `code` and the
  policy's `message`.
- One call at a time: a second waits for the first to end, and a stream holds its turn until it
  ends or is cancelled (`stream.cancel()`). The enclave serves a key one call at a time anyway.
- A message is at most 4 MiB.
- `signRound` returns one `{ hiding, binding, share }` per message. It is half a signature and no
  more: the enclave makes the other half, and only as its policy allows. It signs what it is
  given, so the app checks what a policy asks it to sign before it calls this.

In Rust these are the client's two modules: `net` (the connection, sign-in and calls) and `core`
(the key from the passkey, the record, and the phone's half of a signing round).

## In an app

- **Android** is 64-bit only: build just `arm64-v8a` and `x86_64` (`reactNativeArchitectures` in
  the app's `gradle.properties`).
- **iOS** needs one more package named in the app itself:

  ```sh
  npm install uniffi-bindgen-react-native@0.31.0-7
  ```

  This library's pod depends on that package's pod at exactly the version this library was
  generated with. React Native links only the pods of an app's own dependencies, and CocoaPods
  does not always have that version, so the app names it and the pod comes from `node_modules`.
  Use the version in this package's `dependencies`. The example app does the same from its
  `react-native.config.js`.

## Building

`android/`, `ios/`, `cpp/`, `src/` and the podspec are generated from `rust/vtxos-uniffi`
and not committed. Generate them, with the libraries, for one platform or both:

```sh
yarn                # Node from .nvmrc; Yarn through corepack
yarn ubrn:android   # arm64-v8a and x86_64, with cargo-ndk and NDK 27 (ANDROID_NDK_HOME)
yarn ubrn:ios       # devices and the simulator, into an xcframework; macOS only
yarn typecheck
```

Each needs its Rust targets: `aarch64-linux-android` and `x86_64-linux-android`, or
`aarch64-apple-ios` and `aarch64-apple-ios-sim`.
[`scripts/ci-mobile-android.sh`](../../scripts/ci-mobile-android.sh) and
[`scripts/ci-mobile-ios.sh`](../../scripts/ci-mobile-ios.sh) do exactly what a release does, and
build the example app against the result.

## Releasing

A tag named `react-native-wallet-v<version>` on `main` publishes that version to npm
([the workflow](../../.github/workflows/react-native-release.yml)): both platforms are built, and
only if both pass is the package published. A version with a hyphen, such as `0.1.0-rc.2`, goes
out under the `next` tag. To try the builds without publishing, push a branch named
`release-trial/<anything>`.

## The example app

The example talks to the runtime running in process on this machine, serving your policy guest.
This repository holds no policy: build your own, and name its component here.

```sh
(cd clients/react-native/rust && POLICY_WASM=<path to your policy's wasm> cargo run -p vtxos-uniffi --example dev_enclave)
```

It prints an `adb reverse` command, which lets an emulator reach it, and a line of settings (the
URL and pins). Then:

```sh
yarn example android
```

Paste the settings line into the app and register. It then calls whatever method you name with
whatever bytes you give it, as hex, and shows the reply.

## Testing an app's own messages

An app that runs a policy's conversations in TypeScript cannot load this library's native half in
Node. `cargo run -p vtxos-uniffi --example bridge` is the same exported API with one JSON object
per line on stdin and stdout, over the runtime in process and the app's own policy guest
(`POLICY_WASM`), so the app's code can be tested against what it meets on a phone.
