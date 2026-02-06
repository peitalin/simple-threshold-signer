#!/bin/bash

# Helper for ensuring a wasm32-unknown-unknown capable C toolchain is available.
# Some Rust dependencies (e.g. blst via blstrs) compile C sources for wasm targets.
# Apple clang does not ship with a wasm backend, so macOS builds often require
# Homebrew LLVM (or another wasm-capable clang).

ensure_wasm32_cc() {
  if [ -n "${CC_wasm32_unknown_unknown:-}" ]; then
    return 0
  fi

  local test_dir cc_path llvm_prefix
  test_dir="$(mktemp -d)"

  printf 'int main(void) { return 0; }\n' >"$test_dir/test.c"

  _wasm_cc_supports_target() {
    local candidate="$1"
    "$candidate" --target=wasm32-unknown-unknown -c "$test_dir/test.c" -o "$test_dir/test.o" >/dev/null 2>&1
  }

  if command -v clang >/dev/null 2>&1; then
    cc_path="$(command -v clang)"
    if _wasm_cc_supports_target "$cc_path"; then
      export CC_wasm32_unknown_unknown="$cc_path"
      rm -rf "$test_dir" 2>/dev/null || true
      return 0
    fi
  fi

  if command -v brew >/dev/null 2>&1; then
    llvm_prefix="$(brew --prefix llvm 2>/dev/null || true)"
    if [ -n "$llvm_prefix" ] && [ -x "$llvm_prefix/bin/clang" ] && _wasm_cc_supports_target "$llvm_prefix/bin/clang"; then
      export CC_wasm32_unknown_unknown="$llvm_prefix/bin/clang"
      if [ -x "$llvm_prefix/bin/llvm-ar" ]; then
        export AR_wasm32_unknown_unknown="$llvm_prefix/bin/llvm-ar"
      fi
      rm -rf "$test_dir" 2>/dev/null || true
      return 0
    fi
  fi

  if [ -x "/opt/homebrew/opt/llvm/bin/clang" ] && _wasm_cc_supports_target "/opt/homebrew/opt/llvm/bin/clang"; then
    export CC_wasm32_unknown_unknown="/opt/homebrew/opt/llvm/bin/clang"
    if [ -x "/opt/homebrew/opt/llvm/bin/llvm-ar" ]; then
      export AR_wasm32_unknown_unknown="/opt/homebrew/opt/llvm/bin/llvm-ar"
    fi
    rm -rf "$test_dir" 2>/dev/null || true
    return 0
  fi

  rm -rf "$test_dir" 2>/dev/null || true

  echo "❌ Missing a wasm32-unknown-unknown capable C compiler."
  echo ""
  echo "This repo's wasm builds can transitively depend on C code (e.g. blst), and Apple clang"
  echo "does not support '--target=wasm32-unknown-unknown'."
  echo ""
  echo "Fix options:"
  echo "  - macOS (recommended): brew install llvm"
  echo "    Then re-run with:"
  echo "      export CC_wasm32_unknown_unknown=\"\$(brew --prefix llvm)/bin/clang\""
  echo "  - Or set CC_wasm32_unknown_unknown to any clang that supports wasm targets."
  echo ""
  return 1
}
