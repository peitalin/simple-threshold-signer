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

echo "[check-signing-architecture] checking execute helper context enforcement..."
if rg -n \
  -e "requestMultichainWorkerOperation" \
  client/src/core/signing/chainAdaptors/handlers/executeSignerWorkerOperation.ts; then
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

echo "[check-signing-architecture] OK"
