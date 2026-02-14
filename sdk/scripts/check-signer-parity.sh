#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

FEATURES="secp256k1,near-ed25519,near-crypto"
VECTORS_FILE="crates/signer-core/fixtures/signing-vectors/v1.json"
WEB_WASM_REPLAY_TEST="./unit/signingVectors.webWasmReplay.unit.test.ts"
IOS_SWIFT_REPLAY_SCRIPT="crates/signer-platform-ios/scripts/run-swift-vector-replay.sh"

echo "[check-signer-parity] checking canonical vector fixture..."
if [[ ! -f "$VECTORS_FILE" ]]; then
  echo "[check-signer-parity] failed: missing $VECTORS_FILE"
  exit 1
fi

echo "[check-signer-parity] replaying tx-finalization vectors through signer-core..."
cargo test \
  --manifest-path crates/signer-core/Cargo.toml \
  --locked \
  --features tx-finalization \
  eip1559_vectors_are_stable
cargo test \
  --manifest-path crates/signer-core/Cargo.toml \
  --locked \
  --features tx-finalization \
  tempo_vectors_are_stable
echo "[check-signer-parity] replaying shared baseline vectors through signer-core..."
cargo test \
  --manifest-path crates/signer-core/Cargo.toml \
  --locked \
  --features "$FEATURES" \
  vectors_v1_match_expected_outputs

echo "[check-signer-parity] replaying vectors through signer-platform-web..."
cargo test \
  --manifest-path crates/signer-platform-web/Cargo.toml \
  --locked \
  --features "$FEATURES" \
  vectors_v1_match_expected_outputs

echo "[check-signer-parity] replaying vectors through signer-platform-ios..."
cargo test \
  --manifest-path crates/signer-platform-ios/Cargo.toml \
  --locked \
  --features "$FEATURES" \
  vectors_v1_match_expected_outputs

if [[ "${RUN_IOS_SWIFT_REPLAY:-0}" == "1" ]]; then
  echo "[check-signer-parity] replaying vectors through iOS Swift harness..."
  "$IOS_SWIFT_REPLAY_SCRIPT"
else
  echo "[check-signer-parity] skipping iOS Swift replay parity test (scaffold-only mode; set RUN_IOS_SWIFT_REPLAY=1 to enable)"
fi

if [[ "${SKIP_WEB_WASM_REPLAY:-0}" == "1" ]]; then
  echo "[check-signer-parity] skipping Web WASM replay parity test (SKIP_WEB_WASM_REPLAY=1)"
else
  echo "[check-signer-parity] replaying vectors through Web WASM worker-facing bindings..."
  pnpm -C sdk run build:check:fresh >/dev/null 2>&1 || pnpm -C sdk run build
  pnpm -C tests exec playwright test "$WEB_WASM_REPLAY_TEST" --reporter=line
fi

echo "[check-signer-parity] OK"
