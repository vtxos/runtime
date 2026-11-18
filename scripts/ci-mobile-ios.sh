#!/usr/bin/env bash
# The React Native package on iOS: clients/mobile/vtxos-uniffi built for devices
# and the simulator into an xcframework, its bindings and Turbo Module generated
# by uniffi-bindgen-react-native, and the example app built for the simulator.
#
# Needs macOS with Xcode and CocoaPods, protoc (vtxos-client's build script), and
# Node with corepack.

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO"

say "ios: toolchain"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim

cd "$REPO/clients/react-native"
corepack enable
yarn install --immutable

say "ios: the library, its bindings and Turbo Module"
# Also installs the example's pods, which compile the generated C++.
yarn ubrn:ios

say "ios: TypeScript"
yarn typecheck

say "ios: the example app, for the simulator"
# arm64 only: the xcframework has no x86_64 simulator slice (ubrn.config.yaml).
xcodebuild build \
    -workspace example/ios/ReactNativeWalletExample.xcworkspace \
    -scheme ReactNativeWalletExample \
    -configuration Debug \
    -sdk iphonesimulator \
    -destination 'generic/platform=iOS Simulator' \
    ARCHS=arm64 \
    CODE_SIGNING_ALLOWED=NO
