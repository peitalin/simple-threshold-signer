#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CRATE_DIR="$ROOT_DIR/crates/signer-platform-ios"
SWIFT_HARNESS="$CRATE_DIR/swift/VectorReplay.swift"
VECTORS_FILE="$ROOT_DIR/crates/signer-core/fixtures/signing-vectors/v1.json"
FEATURES="${IOS_SIGNER_FEATURES:-secp256k1,near-ed25519,near-crypto}"

if ! command -v swift >/dev/null 2>&1; then
  echo "[ios-swift-replay] failed: swift toolchain is required"
  exit 1
fi

if [[ ! -f "$SWIFT_HARNESS" ]]; then
  echo "[ios-swift-replay] failed: missing harness at $SWIFT_HARNESS"
  exit 1
fi

if [[ ! -f "$VECTORS_FILE" ]]; then
  echo "[ios-swift-replay] failed: missing vectors file at $VECTORS_FILE"
  exit 1
fi

echo "[ios-swift-replay] building signer-platform-ios cdylib..."
cargo build \
  --manifest-path "$CRATE_DIR/Cargo.toml" \
  --locked \
  --features "$FEATURES"

LIB_PATH="$(find "$CRATE_DIR/target/debug" -maxdepth 2 -name "libsigner_platform_ios.dylib" -print -quit)"
if [[ -z "$LIB_PATH" ]]; then
  echo "[ios-swift-replay] failed: could not find libsigner_platform_ios.dylib"
  exit 1
fi

LIB_DIR="$(dirname "$LIB_PATH")"
OUT_DIR="$CRATE_DIR/target/swift"
BIN_PATH="$OUT_DIR/vector-replay"
MODULE_CACHE_DIR="$OUT_DIR/module-cache"

mkdir -p "$OUT_DIR"
mkdir -p "$MODULE_CACHE_DIR"

echo "[ios-swift-replay] compiling swift harness..."
swiftc \
  "$SWIFT_HARNESS" \
  -module-cache-path "$MODULE_CACHE_DIR" \
  -L "$LIB_DIR" \
  -l signer_platform_ios \
  -Xlinker -rpath \
  -Xlinker "$LIB_DIR" \
  -o "$BIN_PATH"

echo "[ios-swift-replay] running swift harness..."
DYLD_LIBRARY_PATH="$LIB_DIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
  "$BIN_PATH" \
  "$VECTORS_FILE"

echo "[ios-swift-replay] OK"
