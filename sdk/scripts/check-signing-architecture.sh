#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "[check-signing-architecture] checking for legacy signing symbols..."
if rg -n \
  -e "SigningWorkerManager" \
  -e "MultichainSignerRuntimeDeps" \
  -e "requestNearWorkerOperation" \
  -e "executeNearWorkerOperation" \
  -e "executeMultichainWorkerOperation" \
  -e "workers/signingWorkerManager" \
  client/src/core/signing \
  tests; then
  echo "[check-signing-architecture] failed: found legacy symbols"
  exit 1
fi

echo "[check-signing-architecture] checking chain import boundaries..."
if rg -n \
  -e "workers/signerWorkerManager/backends/nearWorkerBackend" \
  -e "workers/signerWorkerManager/backends/multichainWorkerBackend" \
  client/src/core/signing/chainAdaptors; then
  echo "[check-signing-architecture] failed: chain modules import backend implementations directly"
  exit 1
fi

echo "[check-signing-architecture] checking legacy execute helper path removal..."
if rg -n \
  -e "chainAdaptors/handlers/executeSignerWorkerOperation" \
  client/src/core/signing \
  tests \
  docs; then
  echo "[check-signing-architecture] failed: found stale executeSignerWorkerOperation import/docs path"
  exit 1
fi

echo "[check-signing-architecture] checking chain adaptor barrel boundaries..."
if rg -n \
  -e "export \\* from '\\./(bytes|eip1559|keccak|rlp|tempoTx|deriveSecp256k1KeypairFromPrfSecond)'" \
  client/src/core/signing/chainAdaptors/evm/index.ts \
  client/src/core/signing/chainAdaptors/tempo/index.ts; then
  echo "[check-signing-architecture] failed: chain adaptor barrels must not re-export low-level crypto modules"
  exit 1
fi

echo "[check-signing-architecture] checking TS crypto helper cleanup..."
if rg -n \
  -e "chainAdaptors/evm/(eip1559|keccak|rlp)" \
  -e "chainAdaptors/tempo/tempoTx" \
  -e "chainAdaptors/evm/deriveSecp256k1KeypairFromPrfSecond" \
  client/src/core/signing \
  tests; then
  echo "[check-signing-architecture] failed: runtime/tests must not import removed TS crypto helpers"
  exit 1
fi

for stale_file in \
  client/src/core/signing/chainAdaptors/evm/eip1559.ts \
  client/src/core/signing/chainAdaptors/evm/keccak.ts \
  client/src/core/signing/chainAdaptors/evm/rlp.ts \
  client/src/core/signing/chainAdaptors/tempo/tempoTx.ts \
  client/src/core/signing/chainAdaptors/evm/deriveSecp256k1KeypairFromPrfSecond.ts; do
  if [[ -e "$stale_file" ]]; then
    echo "[check-signing-architecture] failed: stale TS crypto helper still exists: $stale_file"
    exit 1
  fi
done

echo "[check-signing-architecture] checking runtime signing noble imports..."
if rg -n \
  -e "@noble/" \
  client/src/core/signing; then
  echo "[check-signing-architecture] failed: runtime signing path must not import noble crypto modules directly"
  exit 1
fi

echo "[check-signing-architecture] checking execute helper context enforcement..."
if rg -n \
  -e "requestMultichainWorkerOperation" \
  client/src/core/signing/workers/operations/executeSignerWorkerOperation.ts; then
  echo "[check-signing-architecture] failed: execute helper must dispatch through runtime context only"
  exit 1
fi

echo "[check-signing-architecture] checking worker contract version guardrails..."
if ! rg -n \
  -e "resolveSignerWorkerContractVersion" \
  client/src/core/signing/workers/signerWorkerManager/backends/multichainWorkerBackend.ts \
  client/src/core/signing/workers/signerWorkerManager/backends/nearWorkerBackend.ts \
  client/src/core/workers/eth-signer.worker.ts \
  client/src/core/workers/tempo-signer.worker.ts >/dev/null; then
  echo "[check-signing-architecture] failed: signer worker backends/workers must enforce contract version guardrails"
  exit 1
fi

echo "[check-signing-architecture] checking SecureConfirm wrapper cleanup..."
if rg -n \
  -e "secureConfirm/flow/" \
  client/src/core/signing \
  tests; then
  echo "[check-signing-architecture] failed: secureConfirm/flow wrapper imports should be removed"
  exit 1
fi

echo "[check-signing-architecture] checking WebAuthn P-256 wasm boundary..."
if rg -n \
  -e "parseDerEcdsaSignatureP256" \
  -e "readDerLength\\(" \
  client/src/core/signing/engines/webauthnP256.ts; then
  echo "[check-signing-architecture] failed: WebAuthn P-256 DER parsing must live in wasm worker path"
  exit 1
fi

echo "[check-signing-architecture] checking NEAR derivation wasm boundary..."
if rg -n \
  -e "deriveNearKeypairFromPrfSecondB64u" \
  client/src/core/signing \
  client/src/core/TatchiPasskey \
  tests; then
  echo "[check-signing-architecture] failed: deterministic NEAR PRF.second derivation must route through near-signer wasm worker"
  exit 1
fi

if rg -n \
  -e "near-key-derivation:" \
  -e "ed25519-signing-key-dual-prf-v1" \
  client/src/core/near/nearCrypto.ts; then
  echo "[check-signing-architecture] failed: deterministic NEAR PRF.second derivation logic must not live in nearCrypto.ts"
  exit 1
fi

echo "[check-signing-architecture] checking threshold-only secp256k1 runtime signing..."
if rg -n \
  -e "local-secp256k1" \
  client/src/core/signing/engines/secp256k1.ts \
  client/src/core/signing/api/WebAuthnManager.ts \
  client/src/core/signing/chainAdaptors/tempo/handlers/signTempoWithSecureConfirm.ts; then
  echo "[check-signing-architecture] failed: runtime secp256k1 signing path must not accept local-secp256k1 key refs"
  exit 1
fi

if ! rg -n \
  -e "runtime signing requires threshold-ecdsa-secp256k1 keyRef" \
  client/src/core/signing/engines/secp256k1.ts >/dev/null; then
  echo "[check-signing-architecture] failed: secp256k1 engine must enforce threshold-ecdsa-secp256k1 key refs"
  exit 1
fi

echo "[check-signing-architecture] checking export-only local-key runtime guardrails..."
if ! rg -n \
  -e "export-only local key material" \
  client/src/core/signing/chainAdaptors/near/handlers/signTransactionsWithActions.ts \
  client/src/core/signing/chainAdaptors/near/handlers/signDelegateAction.ts \
  client/src/core/signing/chainAdaptors/near/handlers/signNep413Message.ts >/dev/null; then
  echo "[check-signing-architecture] failed: NEAR runtime signing handlers must guard against export-only local keys"
  exit 1
fi

echo "[check-signing-architecture] checking secp256k1 derivation stays export-only..."
if rg -n \
  -e "deriveSecp256k1KeypairFromPrfSecondWasm\\(" \
  client/src/core/signing \
  client/src/core/TatchiPasskey \
  | rg -v "client/src/core/signing/api/WebAuthnManager.ts" \
  | rg -v "client/src/core/signing/chainAdaptors/evm/ethSignerWasm.ts" >/dev/null; then
  echo "[check-signing-architecture] failed: secp256k1 local derivation must be restricted to export UX wiring"
  exit 1
fi

echo "[check-signing-architecture] checking smart-account deployment mode default..."
if ! rg -n \
  -e "smartAccountDeploymentMode: 'enforce'" \
  client/src/core/config/defaultConfigs.ts >/dev/null; then
  echo "[check-signing-architecture] failed: smart-account deployment mode must default to enforce"
  exit 1
fi

if ! rg -n \
  -e "smartAccountDeploymentMode === 'observe'" \
  client/src/core/config/defaultConfigs.ts >/dev/null; then
  echo "[check-signing-architecture] failed: config merge must support explicit observe override"
  exit 1
fi

echo "[check-signing-architecture] checking rust signer platform boundary..."
if [[ ! -f "crates/signer-core/Cargo.toml" ]]; then
  echo "[check-signing-architecture] failed: missing crates/signer-core/Cargo.toml"
  exit 1
fi

if [[ ! -f "crates/signer-platform-web/Cargo.toml" ]]; then
  echo "[check-signing-architecture] failed: missing crates/signer-platform-web/Cargo.toml"
  exit 1
fi

if ! rg -n \
  -e "signer-core = \\{ path = \"\\.\\./signer-core\"" \
  crates/signer-platform-web/Cargo.toml >/dev/null; then
  echo "[check-signing-architecture] failed: signer-platform-web must depend on signer-core via local path"
  exit 1
fi

if [[ ! -f "crates/signer-platform-ios/Cargo.toml" ]]; then
  echo "[check-signing-architecture] failed: missing crates/signer-platform-ios/Cargo.toml"
  exit 1
fi

if ! rg -n \
  -e "signer-core = \\{ path = \"\\.\\./signer-core\"" \
  crates/signer-platform-ios/Cargo.toml >/dev/null; then
  echo "[check-signing-architecture] failed: signer-platform-ios must depend on signer-core via local path"
  exit 1
fi

if rg -n \
  -e "wasm-bindgen" \
  crates/signer-platform-ios/Cargo.toml \
  crates/signer-platform-ios/src >/dev/null; then
  echo "[check-signing-architecture] failed: signer-platform-ios must remain platform-native (no wasm-bindgen dependency)"
  exit 1
fi

if ! rg -n \
  -e "pub mod v1" \
  crates/signer-platform-ios/src/lib.rs >/dev/null; then
  echo "[check-signing-architecture] failed: signer-platform-ios must expose a versioned API module (v1)"
  exit 1
fi

if [[ ! -f "crates/signer-core/fixtures/signing-vectors/v1.json" ]]; then
  echo "[check-signing-architecture] failed: missing canonical signer vector corpus at crates/signer-core/fixtures/signing-vectors/v1.json"
  exit 1
fi

if ! rg -n \
  -e "vectors_v1_match_expected_outputs" \
  crates/signer-platform-web/src/lib.rs \
  crates/signer-platform-web/src/tests.rs \
  crates/signer-platform-ios/src/lib.rs \
  crates/signer-platform-ios/src/tests.rs >/dev/null; then
  echo "[check-signing-architecture] failed: web and ios platform bindings must replay canonical vector corpus in tests"
  exit 1
fi

if [[ ! -x "crates/signer-platform-ios/scripts/run-swift-vector-replay.sh" ]]; then
  echo "[check-signing-architecture] failed: missing executable iOS Swift replay script"
  exit 1
fi

if [[ ! -f "crates/signer-platform-ios/swift/VectorReplay.swift" ]]; then
  echo "[check-signing-architecture] failed: missing iOS Swift replay harness source"
  exit 1
fi

if ! rg -n \
  -e "signer_platform_ios_v1_hex_to_bytes_hex" \
  -e "signer_platform_ios_string_free" \
  crates/signer-platform-ios/src/lib.rs >/dev/null; then
  echo "[check-signing-architecture] failed: signer-platform-ios must expose a stable Swift-facing C ABI surface"
  exit 1
fi

if ! rg -n \
  -e "run-swift-vector-replay\\.sh" \
  sdk/scripts/check-signer-parity.sh >/dev/null; then
  echo "[check-signing-architecture] failed: check-signer-parity must include iOS Swift replay harness"
  exit 1
fi

if ! rg -n \
  -e "signer-platform-web = \\{ path = \"\\.\\./\\.\\./crates/signer-platform-web\"" \
  wasm/eth_signer/Cargo.toml \
  wasm/tempo_signer/Cargo.toml \
  wasm/near_signer/Cargo.toml >/dev/null; then
  echo "[check-signing-architecture] failed: wasm signer crates must depend on signer-platform-web via local path"
  exit 1
fi

if rg -n \
  -e "signer-core = \\{" \
  wasm/eth_signer/Cargo.toml \
  wasm/tempo_signer/Cargo.toml \
  wasm/near_signer/Cargo.toml >/dev/null; then
  echo "[check-signing-architecture] failed: wasm signer crates must not depend on signer-core directly"
  exit 1
fi

if ! rg -n -e "signer_platform_web::codec::" \
  wasm/eth_signer/src/codec.rs \
  wasm/tempo_signer/src/codec.rs >/dev/null; then
  echo "[check-signing-architecture] failed: wasm codec wrappers must delegate to signer-platform-web::codec"
  exit 1
fi

if ! rg -n -e "signer_platform_web::secp256k1::" \
  wasm/eth_signer/src/derive.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth derive wrapper must delegate to signer-platform-web::secp256k1"
  exit 1
fi

if ! rg -n -e "signer_platform_web::secp256k1::sign_secp256k1_recoverable" \
  wasm/eth_signer/src/secp256k1_sign.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth secp256k1_sign wrapper must delegate to signer-platform-web::secp256k1"
  exit 1
fi

if ! rg -n \
  -e "signer_platform_web::threshold_ecdsa::threshold_ecdsa_compute_signature_share" \
  -e "signer_platform_web::threshold_ecdsa::threshold_ecdsa_finalize_signature" \
  wasm/eth_signer/src/threshold.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth threshold wrapper must delegate compute/finalize to signer-platform-web::threshold_ecdsa"
  exit 1
fi

if ! rg -n \
  -e "signer_platform_web::threshold_ecdsa::ThresholdEcdsaPresignSession::new" \
  wasm/eth_signer/src/threshold.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth threshold wrapper must delegate presign session construction to signer-platform-web::threshold_ecdsa"
  exit 1
fi

if ! rg -n -e "signer_platform_web::eip1559::" \
  wasm/eth_signer/src/eip1559.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth eip1559 wrapper must delegate to signer-platform-web::eip1559"
  exit 1
fi

if ! rg -n -e "signer_platform_web::webauthn_p256::" \
  wasm/eth_signer/src/webauthn_p256.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth webauthn_p256 wrapper must delegate to signer-platform-web::webauthn_p256"
  exit 1
fi

if rg -n \
  -e "use crate::codec::" \
  -e "Keccak256" \
  wasm/eth_signer/src/eip1559.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth eip1559 wrapper must not contain local hashing/encoding logic"
  exit 1
fi

if rg -n \
  -e "k256::" \
  -e "normalize_s\\(" \
  wasm/eth_signer/src/secp256k1_sign.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth secp256k1_sign wrapper must not contain local secp256k1 math/normalization"
  exit 1
fi

if rg -n \
  -e "RerandomizedPresignOutput::rerandomize_presign" \
  -e "RecoveryId::from_byte" \
  -e "final signature failed to verify" \
  wasm/eth_signer/src/threshold.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth threshold wrapper must not contain local compute/finalize signature math"
  exit 1
fi

if rg -n \
  -e "threshold_signatures::" \
  -e "generate_triple_many" \
  -e "presign::presign" \
  wasm/eth_signer/src/threshold.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth threshold wrapper must not contain local threshold protocol orchestration logic"
  exit 1
fi

if rg -n \
  -e "read_der_length\\(" \
  -e "parse_der_ecdsa_signature_p256\\(" \
  -e "base64url_encode_no_pad\\(" \
  wasm/eth_signer/src/webauthn_p256.rs >/dev/null; then
  echo "[check-signing-architecture] failed: eth webauthn_p256 wrapper must not contain local DER/base64url parsing logic"
  exit 1
fi

if ! rg -n -e "signer_platform_web::tempo_tx::" \
  wasm/tempo_signer/src/tempo_tx.rs >/dev/null; then
  echo "[check-signing-architecture] failed: tempo tx wrapper must delegate to signer-platform-web::tempo_tx"
  exit 1
fi

if rg -n \
  -e "use crate::codec::" \
  -e "Keccak256" \
  wasm/tempo_signer/src/tempo_tx.rs >/dev/null; then
  echo "[check-signing-architecture] failed: tempo tx wrapper must not contain local hashing/encoding logic"
  exit 1
fi

if ! rg -n -e "signer_platform_web::near_ed25519::derive_ed25519_key_from_prf_output" \
  wasm/near_signer/src/crypto.rs >/dev/null; then
  echo "[check-signing-architecture] failed: near ed25519 derivation must delegate to signer-platform-web::near_ed25519"
  exit 1
fi

if ! rg -n -e "signer_platform_web::near_crypto::" \
  wasm/near_signer/src/crypto.rs >/dev/null; then
  echo "[check-signing-architecture] failed: near KEK/ChaCha20 helpers must delegate to signer-platform-web::near_crypto"
  exit 1
fi

if ! rg -n -e "signer_platform_web::near_threshold_ed25519::" \
  wasm/near_signer/src/threshold/threshold_client_share.rs >/dev/null; then
  echo "[check-signing-architecture] failed: near threshold client-share wrapper must delegate to signer-platform-web::near_threshold_ed25519"
  exit 1
fi

if ! rg -n -e "signer_platform_web::near_threshold_ed25519::" \
  wasm/near_signer/src/threshold/protocol.rs \
  wasm/near_signer/src/threshold/participant_ids.rs >/dev/null; then
  echo "[check-signing-architecture] failed: near threshold protocol/participant wrappers must delegate to signer-platform-web::near_threshold_ed25519"
  exit 1
fi

if rg -n \
  -e "Hkdf::" \
  -e "from_bytes_mod_order_wide" \
  wasm/near_signer/src/threshold/threshold_client_share.rs \
  | rg -v "#\\[cfg\\(test\\)\\]" >/dev/null; then
  echo "[check-signing-architecture] failed: near threshold client-share wrapper must not contain local runtime HKDF/curve math"
  exit 1
fi

if rg -n \
  -e "frost_ed25519::round1::commit" \
  -e "base64_url_decode\\(" \
  -e "base64_url_encode\\(" \
  wasm/near_signer/src/threshold/protocol.rs >/dev/null; then
  echo "[check-signing-architecture] failed: near threshold protocol wrapper must not contain local runtime commit/base64 protocol logic"
  exit 1
fi

if ! rg -n \
  -e "signer_platform_web::near_threshold_ed25519::parse_near_public_key_to_bytes" \
  -e "signer_platform_web::near_threshold_ed25519::derive_client_key_package_from_wrap_key_seed_b64u" \
  wasm/near_signer/src/threshold/signer_backend.rs >/dev/null; then
  echo "[check-signing-architecture] failed: near signer_backend must delegate key parsing/package derivation to signer-platform-web::near_threshold_ed25519"
  exit 1
fi

if rg -n \
  -e "fn parse_near_public_key_to_bytes\\(" \
  -e "fn derive_client_key_package_from_wrap_key_seed\\(" \
  wasm/near_signer/src/threshold/signer_backend.rs >/dev/null; then
  echo "[check-signing-architecture] failed: near signer_backend must not keep local key parsing/package derivation helpers"
  exit 1
fi

if ! rg -n \
  -e "signer_platform_web::near_threshold_ed25519::parse_near_public_key_to_bytes" \
  -e "signer_platform_web::near_threshold_ed25519::compute_nep413_signing_digest_from_nonce_base64" \
  wasm/near_signer/src/threshold/threshold_digests.rs >/dev/null; then
  echo "[check-signing-architecture] failed: near threshold_digests wrapper must delegate key parsing + nep413 digest to signer-platform-web::near_threshold_ed25519"
  exit 1
fi

if rg -n \
  -e "base64_standard_decode\\(" \
  -e "borsh::to_vec\\(&payload_borsh\\)" \
  wasm/near_signer/src/threshold/threshold_digests.rs >/dev/null; then
  echo "[check-signing-architecture] failed: near threshold_digests wrapper must not contain local nonce decode/borsh hashing logic for NEP-413"
  exit 1
fi

if rg -n \
  -e "signer_core::" \
  wasm/eth_signer/src/codec.rs \
  wasm/eth_signer/src/derive.rs \
  wasm/tempo_signer/src/codec.rs \
  wasm/near_signer/src/crypto.rs >/dev/null; then
  echo "[check-signing-architecture] failed: wasm wrappers must not call signer-core directly"
  exit 1
fi

echo "[check-signing-architecture] OK"
