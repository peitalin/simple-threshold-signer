#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '..'));

const wasmPkgJsAbs = path.join(sdkRoot, 'dist', 'esm', 'server', 'wasm', 'eth_signer', 'pkg', 'eth_signer.js');
const sourceWasmAbs = path.join(sdkRoot, '..', 'wasm', 'eth_signer', 'pkg', 'eth_signer_bg.wasm');

function fail(msg) {
  console.error(`\n[smoke-eth-signer-node-runtime] ${msg}`);
  process.exit(1);
}

if (!fs.existsSync(wasmPkgJsAbs)) {
  fail(`Missing wasm-bindgen JS at ${wasmPkgJsAbs}. Run 'pnpm -C sdk build:prod' first.`);
}
if (!fs.existsSync(sourceWasmAbs)) {
  fail(`Missing source WASM at ${sourceWasmAbs}.`);
}

const mod = await import(pathToFileURL(wasmPkgJsAbs).href);
const initWasm = mod.default || mod.__wbg_init;
if (typeof initWasm !== 'function') fail('eth_signer init export is missing (expected default or __wbg_init)');
if (typeof mod.init_eth_signer !== 'function') fail('eth_signer init_eth_signer export is missing');
if (typeof mod.threshold_ecdsa_finalize_signature !== 'function') {
  fail('eth_signer threshold_ecdsa_finalize_signature export is missing');
}

const sourceWasmBytes = fs.readFileSync(sourceWasmAbs);
const sourceWasmBuffer = new ArrayBuffer(sourceWasmBytes.byteLength);
new Uint8Array(sourceWasmBuffer).set(sourceWasmBytes);
const compiledModule = await WebAssembly.compile(sourceWasmBuffer);

await initWasm({ module_or_path: compiledModule });
mod.init_eth_signer();

console.log('[smoke-eth-signer-node-runtime] OK');
