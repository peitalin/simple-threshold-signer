#!/bin/bash

# Centralized build configuration (bash version)
# This file defines all paths used across the build system

# Build output directories
BUILD_ROOT="dist"
BUILD_WORKERS="dist/workers"
BUILD_ESM="dist/esm"
BUILD_CJS="dist/cjs"
BUILD_TYPES="dist/types"

# Source directories
SOURCE_ROOT="src"
SOURCE_CORE="src/core"
SOURCE_WASM_SIGNER="src/wasm_near_signer"
SOURCE_WASM_ETH_SIGNER="src/wasm_eth_signer"
SOURCE_WASM_TEMPO_SIGNER="src/wasm_tempo_signer"

# Critical directories for build freshness checking
CRITICAL_DIRS=(
    "src/core"
    "src/react"
    "src/server"
    "src/wasm_near_signer"
    "src/wasm_eth_signer"
    "src/wasm_tempo_signer"
)

# Example Vite app deployment paths (used only for local dev/test copying)
FRONTEND_ROOT="../examples/vite/public"
FRONTEND_SDK="../examples/vite/public/sdk"
FRONTEND_WORKERS="../examples/vite/public/sdk/workers"

# Runtime paths (used by workers and tests)
RUNTIME_SDK_BASE="/sdk"
RUNTIME_WORKERS_BASE="/sdk/workers"
RUNTIME_SECURE_CONFIRM_WORKER="/sdk/workers/web3authn-secure-confirm.worker.js"
RUNTIME_SIGNER_WORKER="/sdk/workers/web3authn-signer.worker.js"

# Worker file names
WORKER_SECURE_CONFIRM="web3authn-secure-confirm.worker.js"
WORKER_SIGNER="web3authn-signer.worker.js"
WORKER_ETH_SIGNER="eth-signer.worker.js"
WORKER_TEMPO_SIGNER="tempo-signer.worker.js"
WORKER_WASM_SIGNER_JS="wasm_signer_worker.js"
WORKER_WASM_SIGNER_WASM="wasm_signer_worker_bg.wasm"
WORKER_WASM_ETH_SIGNER_WASM="eth_signer.wasm"
WORKER_WASM_TEMPO_SIGNER_WASM="tempo_signer.wasm"

# Critical files to check for build freshness
CRITICAL_FILES=(
    "src/core/WebAuthnManager/SecureConfirmWorkerManager/index.ts"
    "src/core/WebAuthnManager/SignerWorkerManager/index.ts"
    "src/core/WebAuthnManager/SignerWorkerManager/handlers"
    "src/core/WebAuthnManager/SecureConfirmWorkerManager/confirmTxFlow"
    "src/core/WebAuthnManager/index.ts"
    "src/core/TatchiPasskey/index.ts"
    "src/core/TatchiPasskey/actions.ts"
    "src/core/TatchiPasskey/login.ts"
    "src/core/TatchiPasskey/registration.ts"
    "src/index.ts"
    "rolldown.config.ts"
    "tsconfig.json"
)

# Helper functions
get_worker_path() {
    echo "${BUILD_WORKERS}/$1"
}

get_runtime_worker_path() {
    echo "${RUNTIME_WORKERS_BASE}/$1"
}

get_frontend_worker_path() {
    echo "${FRONTEND_WORKERS}/$1"
}
