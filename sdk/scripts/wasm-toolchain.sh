#!/bin/bash

# Helper for ensuring a wasm32-unknown-unknown capable C toolchain is available.
# Some Rust dependencies (e.g. blst via blstrs) compile C sources for wasm targets.
# Apple clang does not ship with a wasm backend, so macOS builds often require
# Homebrew LLVM (or another wasm-capable clang).

WASM_TOOLCHAIN_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

wasm_bindgen_toolchain_root() {
  if [ -n "${WASM_BINDGEN_TOOLCHAIN_ROOT:-}" ]; then
    printf '%s\n' "${WASM_BINDGEN_TOOLCHAIN_ROOT}"
    return 0
  fi

  local repo_root
  repo_root="$(cd "$WASM_TOOLCHAIN_SCRIPT_DIR/../.." && pwd)"
  printf '%s\n' "$repo_root/.tooling/wasm-bindgen"
}

wasm_pack_default_cache_dir() {
  local os_name
  os_name="$(uname -s 2>/dev/null || echo "")"
  if [ "$os_name" = "Darwin" ]; then
    printf '%s\n' "$HOME/Library/Caches/.wasm-pack"
    return 0
  fi

  if [ -n "${XDG_CACHE_HOME:-}" ]; then
    printf '%s\n' "$XDG_CACHE_HOME/.wasm-pack"
    return 0
  fi

  printf '%s\n' "$HOME/.cache/.wasm-pack"
}

seed_wasm_pack_cache_if_empty() {
  local target_cache="$1"
  local source_cache
  source_cache="$(wasm_pack_default_cache_dir)"

  if [ ! -d "$source_cache" ]; then
    return 0
  fi

  if [ -n "$(find "$target_cache" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    return 0
  fi

  local copied=0
  if compgen -G "$source_cache/wasm-bindgen-*" >/dev/null 2>&1; then
    cp -R "$source_cache"/wasm-bindgen-* "$target_cache"/ 2>/dev/null || true
    copied=1
  fi
  if compgen -G "$source_cache/wasm-opt-*" >/dev/null 2>&1; then
    cp -R "$source_cache"/wasm-opt-* "$target_cache"/ 2>/dev/null || true
    copied=1
  fi
  if compgen -G "$source_cache/.wasm-bindgen-*.lock" >/dev/null 2>&1; then
    cp "$source_cache"/.wasm-bindgen-*.lock "$target_cache"/ 2>/dev/null || true
    copied=1
  fi
  if compgen -G "$source_cache/.wasm-opt-*.lock" >/dev/null 2>&1; then
    cp "$source_cache"/.wasm-opt-*.lock "$target_cache"/ 2>/dev/null || true
    copied=1
  fi

  if [ "$copied" = "1" ]; then
    echo "[wasm-toolchain] seeded local wasm-pack cache from $source_cache"
  fi
}

ensure_wasm_pack_cache() {
  local target_cache
  if [ -n "${WASM_PACK_CACHE:-}" ]; then
    mkdir -p "$WASM_PACK_CACHE"
    return 0
  fi

  local repo_root
  repo_root="$(cd "$WASM_TOOLCHAIN_SCRIPT_DIR/../.." && pwd)"
  target_cache="${WASM_PACK_CACHE_ROOT:-$repo_root/.tooling/wasm-pack-cache}"
  mkdir -p "$target_cache"
  seed_wasm_pack_cache_if_empty "$target_cache"
  export WASM_PACK_CACHE="$target_cache"
  echo "[wasm-toolchain] WASM_PACK_CACHE=$WASM_PACK_CACHE"
}

resolve_wasm_bindgen_cli_version_from_lockfile() {
  local lock_file="$1"
  if [ -n "${WASM_BINDGEN_CLI_VERSION:-}" ]; then
    printf '%s\n' "${WASM_BINDGEN_CLI_VERSION}"
    return 0
  fi
  if [ ! -f "$lock_file" ]; then
    echo "❌ Missing lockfile: $lock_file" >&2
    return 1
  fi

  local version
  version="$(
    awk '
      $0 == "name = \"wasm-bindgen\"" {
        if (getline > 0 && $1 == "version") {
          gsub(/"/, "", $3);
          print $3;
          exit;
        }
      }
    ' "$lock_file"
  )"
  if [ -z "$version" ]; then
    echo "❌ Unable to resolve wasm-bindgen version from $lock_file" >&2
    return 1
  fi
  printf '%s\n' "$version"
}

resolve_wasm_bindgen_bin_for_version() {
  local expected_version="$1"
  local toolchain_root local_bin local_version global_bin global_version
  toolchain_root="$(wasm_bindgen_toolchain_root)"
  local_bin="$toolchain_root/$expected_version/bin/wasm-bindgen"

  if [ -x "$local_bin" ]; then
    local_version="$("$local_bin" --version 2>/dev/null | awk '{print $2}')"
    if [ "$local_version" = "$expected_version" ]; then
      printf '%s\n' "$local_bin"
      return 0
    fi
  fi

  if command -v wasm-bindgen >/dev/null 2>&1; then
    global_bin="$(command -v wasm-bindgen)"
    global_version="$("$global_bin" --version 2>/dev/null | awk '{print $2}')"
    if [ "$global_version" = "$expected_version" ]; then
      printf '%s\n' "$global_bin"
      return 0
    fi
  fi

  local cache_bin cache_version
  for cache_bin in \
    "$WASM_PACK_CACHE"/wasm-bindgen-*/wasm-bindgen \
    "$(wasm_pack_default_cache_dir)"/wasm-bindgen-*/wasm-bindgen; do
    if [ ! -x "$cache_bin" ]; then
      continue
    fi
    cache_version="$("$cache_bin" --version 2>/dev/null | awk '{print $2}')"
    if [ "$cache_version" = "$expected_version" ]; then
      printf '%s\n' "$cache_bin"
      return 0
    fi
  done

  if [ "${WASM_BINDGEN_AUTO_INSTALL:-0}" = "1" ]; then
    mkdir -p "$toolchain_root/$expected_version"
    echo "Installing wasm-bindgen-cli ${expected_version} into $toolchain_root/$expected_version ..."
    cargo install --locked --version "$expected_version" wasm-bindgen-cli --root "$toolchain_root/$expected_version"
    if [ -x "$local_bin" ]; then
      local_version="$("$local_bin" --version 2>/dev/null | awk '{print $2}')"
      if [ "$local_version" = "$expected_version" ]; then
        printf '%s\n' "$local_bin"
        return 0
      fi
    fi
  fi

  echo "❌ wasm-bindgen CLI ${expected_version} is not available." >&2
  echo "Install a pinned toolchain with one of:" >&2
  echo "  cargo install --locked --version ${expected_version} wasm-bindgen-cli" >&2
  echo "  cargo install --locked --version ${expected_version} wasm-bindgen-cli --root $toolchain_root/${expected_version}" >&2
  echo "Or set WASM_BINDGEN_AUTO_INSTALL=1 to let scripts install into workspace-local tooling." >&2
  return 1
}

with_wasm_bindgen_cli_for_lockfile() {
  local lock_file="$1"
  shift
  local expected_version bindgen_bin
  expected_version="$(resolve_wasm_bindgen_cli_version_from_lockfile "$lock_file")" || return 1
  bindgen_bin="$(resolve_wasm_bindgen_bin_for_version "$expected_version")" || return 1
  export WASM_BINDGEN_CLI_VERSION_RESOLVED="$expected_version"
  WASM_BINDGEN="$bindgen_bin" "$@"
}
