#!/bin/bash

# Development build script for @tatchi-xyz/sdk
# - Faster build (no wasm-pack --release, no bun --minify)
# - Rolldown runs without forcing NODE_ENV=production

set -e

source ./build-paths.sh
source ./scripts/wasm-toolchain.sh
SDK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SDK_ROOT/.." && pwd)"

echo "Starting development build for @tatchi-xyz/sdk..."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() { echo -e "${BLUE}📦 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️ $1${NC}"; }

if command -v bun >/dev/null 2>&1; then BUN_BIN="$(command -v bun)"; elif [ -x "$HOME/.bun/bin/bun" ]; then BUN_BIN="$HOME/.bun/bin/bun"; else BUN_BIN=""; fi

print_step "Checking WASM toolchain (C compiler for wasm32)..."
ensure_wasm32_cc
print_success "WASM toolchain ready"

print_step "Cleaning previous build artifacts..."
rm -rf "$BUILD_ROOT/"
print_success "Build directory cleaned"

print_step "Generating TypeScript types from Rust..."
if ./scripts/generate-types.sh; then print_success "TypeScript types generated successfully"; else print_error "Type generation failed"; exit 1; fi

print_step "Building WASM signer worker (dev)..."
pushd "$SDK_ROOT/$SOURCE_WASM_SIGNER" >/dev/null
if wasm-pack build --target web --out-dir pkg; then print_success "WASM signer worker built"; else print_error "WASM signer build failed"; exit 1; fi
popd >/dev/null

print_step "Building WASM eth signer (dev)..."
pushd "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER" >/dev/null
if wasm-pack build --target web --out-dir pkg; then print_success "WASM eth signer built"; else print_error "WASM eth signer build failed"; exit 1; fi
popd >/dev/null

print_step "Building WASM tempo signer (dev)..."
pushd "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER" >/dev/null
if wasm-pack build --target web --out-dir pkg; then print_success "WASM tempo signer built"; else print_error "WASM tempo signer build failed"; exit 1; fi
popd >/dev/null

print_step "Optimizing wasm-pack metadata for tree-shaking..."
if node ./scripts/fix-wasm-pack-sideeffects.mjs "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg"; then
  print_success "WASM package metadata optimized"
else
  print_warning "Failed to optimize WASM package metadata; bundler may deoptimize tree-shaking"
fi
if node ./scripts/fix-wasm-pack-sideeffects.mjs "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER/pkg" 2>/dev/null; then
  print_success "Eth WASM package metadata optimized"
else
  print_warning "Failed to optimize Eth WASM package metadata"
fi
if node ./scripts/fix-wasm-pack-sideeffects.mjs "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg" 2>/dev/null; then
  print_success "Tempo WASM package metadata optimized"
else
  print_warning "Failed to optimize Tempo WASM package metadata"
fi

print_step "Building TypeScript..."
if npx tsc -p tsconfig.build.json; then print_success "TypeScript compilation completed"; else print_error "TypeScript compilation failed"; exit 1; fi

print_step "Generating CSS variables from palette.json (w3a-components.css)..."
if node ./scripts/generate-w3a-components-css.mjs; then print_success "w3a-components.css generated"; else print_error "Failed to generate w3a-components.css"; exit 1; fi

print_step "Bundling with Rolldown (dev)..."
if npx rolldown -c rolldown.config.ts; then print_success "Rolldown bundling completed"; else print_error "Rolldown bundling failed"; exit 1; fi

print_step "Asserting NEAR signer WASM imports stay within dist/esm..."
if node ./scripts/assert-near-signer-wasm-imports.mjs; then print_success "NEAR signer WASM imports OK"; else print_error "NEAR signer WASM imports invalid"; exit 1; fi

print_step "Bundling browser-embedded SDK assets with Bun (dev, no minify)..."
if [ -z "$BUN_BIN" ]; then print_error "Bun not found. Install Bun or ensure it is on PATH."; exit 1; fi

mkdir -p "$BUILD_ESM/sdk"

# These bundles are loaded directly by browsers from /sdk/* (no bundler/import maps),
# so they must not contain bare module specifiers like `import "idb"`.
if "$BUN_BIN" build "$SDK_ROOT/../client/src/core/WebAuthnManager/LitComponents/confirm-ui.ts" --outfile "$BUILD_ESM/sdk/tx-confirm-ui.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/WalletIframe/host/index.ts" --outfile "$BUILD_ESM/sdk/wallet-iframe-host-runtime.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/WebAuthnManager/LitComponents/IframeTxConfirmer/tx-confirmer-wrapper.ts" --outfile "$BUILD_ESM/sdk/w3a-tx-confirmer.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/WebAuthnManager/LitComponents/ExportPrivateKey/iframe-export-bootstrap-script.ts" --outfile "$BUILD_ESM/sdk/iframe-export-bootstrap.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/WebAuthnManager/LitComponents/ExportPrivateKey/viewer.ts" --outfile "$BUILD_ESM/sdk/export-private-key-viewer.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/WebAuthnManager/LitComponents/HaloBorder/index.ts" --outfile "$BUILD_ESM/sdk/halo-border.js" --format esm --target browser --root "$REPO_ROOT" \
  && "$BUN_BIN" build "$SDK_ROOT/../client/src/core/WebAuthnManager/LitComponents/PasskeyHaloLoading/index.ts" --outfile "$BUILD_ESM/sdk/passkey-halo-loading.js" --format esm --target browser --root "$REPO_ROOT"; then
  print_success "Bun embedded-asset bundling completed"
else
  print_error "Bun embedded-asset bundling failed"; exit 1
fi

print_step "Bundling workers with Bun (dev, no minify)..."

if "$BUN_BIN" build "$SOURCE_CORE/workers/near-signer.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_CORE/workers/passkey-secure-confirm.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_CORE/workers/eth-signer.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]' \
  && "$BUN_BIN" build "$SOURCE_CORE/workers/tempo-signer.worker.ts" --outdir "$BUILD_WORKERS" --format esm --target browser --root "$REPO_ROOT" --entry-naming '[name].[ext]'; then
  print_success "Bun worker bundling completed"
else
  print_error "Bun worker bundling failed"; exit 1
fi

print_step "Copying worker WASM binaries next to worker JS..."
mkdir -p "$BUILD_WORKERS"
if cp "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker_bg.wasm" "$BUILD_WORKERS/" 2>/dev/null; then print_success "Signer WASM copied"; else print_warning "Signer WASM not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_SIGNER/pkg/wasm_signer_worker_bg.wasm" "$BUILD_WORKERS/near_signer.wasm" 2>/dev/null; then print_success "near_signer.wasm copied"; else print_warning "near_signer.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_ETH_SIGNER/pkg/eth_signer_bg.wasm" "$BUILD_WORKERS/eth_signer.wasm" 2>/dev/null; then print_success "eth_signer.wasm copied"; else print_warning "eth_signer.wasm not found"; fi
if cp "$SDK_ROOT/$SOURCE_WASM_TEMPO_SIGNER/pkg/tempo_signer_bg.wasm" "$BUILD_WORKERS/tempo_signer.wasm" 2>/dev/null; then print_success "tempo_signer.wasm copied"; else print_warning "tempo_signer.wasm not found"; fi

print_success "Development build completed successfully!"
