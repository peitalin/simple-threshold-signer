#!/bin/bash

# Script to generate TypeScript types from Rust using wasm-bindgen and validate consistency

set -euo pipefail

# Source build paths
source ./build-paths.sh
source ./scripts/wasm-toolchain.sh
SDK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Generating TypeScript types from Rust using wasm-bindgen..."

# Create log file for capturing detailed output
LOG_FILE="/tmp/type_gen.log"
: >"$LOG_FILE"

# Function to handle errors with more detail
handle_error() {
    local exit_code=$?
    local line_number=$1
    echo ""
    echo "❌ Type generation failed at line $line_number with exit code $exit_code"
    echo ""
    echo "Last few lines of output:"
    tail -10 "$LOG_FILE" 2>/dev/null || echo "No log file available"
    echo ""
    echo "Troubleshooting tips:"
    echo "  1. Check if Rust compilation succeeds:"
    echo "     - cd ../wasm/near_signer && cargo check"
    echo "     - cd ../wasm/eth_signer && cargo check"
    echo "     - cd ../wasm/tempo_signer && cargo check"
    echo "  2. Verify wasm-pack is installed: wasm-pack --version"
    echo "  3. Check for WASM compilation errors in the output above"
    echo "  4. Ensure all Rust dependencies are properly declared"
    echo ""
    echo "macOS note: if you see clang '--target=wasm32-unknown-unknown' errors, install Homebrew LLVM:"
    echo "  brew install llvm"
    echo "  export CC_wasm32_unknown_unknown=\"\$(brew --prefix llvm)/bin/clang\""
    exit $exit_code
}

# Log helper: writes to both console and log file
log() {
    echo "$@" | tee -a "$LOG_FILE"
}

# Run helper: runs a command, streaming stdout/stderr to both console and log file
run() {
    log ""
    log "+ $*"
    "$@" 2>&1 | tee -a "$LOG_FILE"
}

# Set up error handling
trap 'handle_error $LINENO' ERR

# Ensure we can compile C dependencies for wasm32 (e.g. blst).
log ""
log "+ ensure_wasm32_cc"
ensure_wasm32_cc
log "CC_wasm32_unknown_unknown=$CC_wasm32_unknown_unknown"

# 1. Build WASM crates and generate TypeScript definitions
echo "Building WASM near signer worker..."
pushd "$SDK_ROOT/$SOURCE_WASM_SIGNER" >/dev/null

echo "Running cargo check first..."
run cargo check

echo "Running wasm-pack build..."
run wasm-pack build --target web --out-dir pkg --out-name wasm_signer_worker
popd >/dev/null

echo "Building eth signer WASM..."
pushd "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER" >/dev/null
echo "Running cargo check first..."
run cargo check
echo "Running wasm-pack build..."
run wasm-pack build --target web --out-dir pkg --out-name eth_signer
popd >/dev/null

echo "Building tempo signer WASM..."
pushd "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER" >/dev/null
echo "Running cargo check first..."
run cargo check
echo "Running wasm-pack build..."
run wasm-pack build --target web --out-dir pkg --out-name tempo_signer
popd >/dev/null

# 2. Check if wasm-bindgen generated types exist
SIGNER_TYPES="$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker.d.ts"
ETH_TYPES="$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER/pkg/eth_signer.d.ts"
TEMPO_TYPES="$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg/tempo_signer.d.ts"

if [ ! -f "$SIGNER_TYPES" ]; then
    echo "❌ Signer worker TypeScript definitions not found at $SIGNER_TYPES"
    echo "This usually means wasm-pack build failed for the signer worker."
    echo "Check the output above for compilation errors."
    exit 1
fi

if [ ! -f "$ETH_TYPES" ]; then
    echo "❌ Eth signer TypeScript definitions not found at $ETH_TYPES"
    echo "This usually means wasm-pack build failed for the eth signer."
    echo "Check the output above for compilation errors."
    exit 1
fi

if [ ! -f "$TEMPO_TYPES" ]; then
    echo "❌ Tempo signer TypeScript definitions not found at $TEMPO_TYPES"
    echo "This usually means wasm-pack build failed for the tempo signer."
    echo "Check the output above for compilation errors."
    exit 1
fi

echo "✅ TypeScript definitions generated successfully by wasm-bindgen"

# 3. Run type checking to ensure consistency
echo "Running TypeScript type checking (build sources only)..."
if ! run npx tsc --noEmit -p tsconfig.build.json; then
    echo ""
    echo "❌ TypeScript type checking failed"
    echo "This usually means there are type inconsistencies between generated WASM types and TypeScript code."
    echo "Check the TypeScript errors above for details."
    exit 1
fi

echo "✅ Type generation and validation complete!"
echo ""
echo "Generated files:"
echo "  - $SIGNER_TYPES (Signer worker types from wasm-bindgen)"
echo "  - $ETH_TYPES (Eth signer types from wasm-bindgen)"
echo "  - $TEMPO_TYPES (Tempo signer types from wasm-bindgen)"
echo "  - Validated against existing TypeScript codebase"
echo ""

# Clean up log file
rm -f "$LOG_FILE"
