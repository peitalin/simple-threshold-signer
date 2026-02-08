#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '..'));

const wasmPkgJsAbs = path.join(sdkRoot, 'dist', 'esm', 'server', 'wasm', 'eth_signer', 'pkg', 'eth_signer.js');
const workerWasmAbs = path.join(sdkRoot, 'dist', 'workers', 'eth_signer.wasm');

function fail(msg) {
  console.error(`\n[smoke-eth-signer-workers-runtime] ${msg}`);
  process.exit(1);
}

async function fileExists(absPath) {
  try {
    await fs.access(absPath);
    return true;
  } catch {
    return false;
  }
}

if (!(await fileExists(wasmPkgJsAbs))) {
  fail(`Missing wasm-bindgen JS at ${wasmPkgJsAbs}. Run 'pnpm -C sdk build:prod' first.`);
}
if (!(await fileExists(workerWasmAbs))) {
  fail(`Missing worker WASM at ${workerWasmAbs}.`);
}

const mod = await import(pathToFileURL(wasmPkgJsAbs).href);
const initWasm = mod.default || mod.__wbg_init;
if (typeof initWasm !== 'function') fail('eth_signer init export is missing (expected default or __wbg_init)');
if (typeof mod.init_eth_signer !== 'function') fail('eth_signer init_eth_signer export is missing');
if (typeof mod.threshold_ecdsa_finalize_signature !== 'function') {
  fail('eth_signer threshold_ecdsa_finalize_signature export is missing');
}

const originalFetch = globalThis.fetch;
if (typeof originalFetch !== 'function') fail('global fetch is required for workers-runtime smoke check');

globalThis.fetch = async (input, init) => {
  const urlString = (() => {
    if (typeof input === 'string') return input;
    if (input instanceof URL) return input.href;
    if (typeof Request === 'function' && input instanceof Request) return input.url;
    return String(input);
  })();

  if (urlString.startsWith('file://')) {
    const filePath = fileURLToPath(urlString);
    const bytes = await fs.readFile(filePath);
    return new Response(bytes, {
      status: 200,
      headers: {
        'Content-Type': 'application/wasm',
      },
    });
  }

  return await originalFetch(input, init);
};

try {
  await initWasm({ module_or_path: pathToFileURL(workerWasmAbs) });
  mod.init_eth_signer();
} finally {
  globalThis.fetch = originalFetch;
}

console.log('[smoke-eth-signer-workers-runtime] OK');
