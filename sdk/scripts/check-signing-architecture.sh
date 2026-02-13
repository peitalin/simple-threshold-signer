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
  client/src/core/signing \
  tests; then
  echo "[check-signing-architecture] failed: runtime/tests must not import removed TS crypto helpers"
  exit 1
fi

for stale_file in \
  client/src/core/signing/chainAdaptors/evm/eip1559.ts \
  client/src/core/signing/chainAdaptors/evm/keccak.ts \
  client/src/core/signing/chainAdaptors/evm/rlp.ts \
  client/src/core/signing/chainAdaptors/tempo/tempoTx.ts; do
  if [[ -e "$stale_file" ]]; then
    echo "[check-signing-architecture] failed: stale TS crypto helper still exists: $stale_file"
    exit 1
  fi
done

echo "[check-signing-architecture] checking execute helper context enforcement..."
if rg -n \
  -e "requestMultichainWorkerOperation" \
  client/src/core/signing/workers/operations/executeSignerWorkerOperation.ts; then
  echo "[check-signing-architecture] failed: execute helper must dispatch through runtime context only"
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

echo "[check-signing-architecture] OK"
