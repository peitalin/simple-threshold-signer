#!/usr/bin/env node
/**
 * Assert that any built JS that imports the NEAR threshold signer wasm-bindgen
 * glue file resolves to the copy under dist/esm/wasm/near_signer/pkg.
 *
 * This prevents accidental output paths like "../../../../wasm/..." that escape
 * dist/ and only work in a monorepo checkout.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const sdkRoot = path.resolve(path.join(__dirname, '..'));

const distEsmRoot = path.join(sdkRoot, 'dist', 'esm');
const targetAbs = path.join(distEsmRoot, 'wasm', 'near_signer', 'pkg', 'wasm_signer_worker.js');
const targetReal = fs.existsSync(targetAbs) ? fs.realpathSync(targetAbs) : null;

function fail(msg) {
  console.error(`\n[assert-near-signer-wasm-imports] ${msg}`);
  process.exit(1);
}

if (!fs.existsSync(distEsmRoot)) {
  fail(`Missing directory: ${distEsmRoot}. Did you run 'pnpm -C sdk build'?`);
}
if (!targetReal) {
  fail(`Missing NEAR signer wasm JS at: ${targetAbs}`);
}

function* walkJsFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkJsFiles(abs);
      continue;
    }
    if (!entry.isFile()) continue;
    if (!entry.name.endsWith('.js')) continue;
    if (abs === targetAbs) continue;
    yield abs;
  }
}

const importRe = /['"]([^'"]*wasm\/near_signer\/pkg\/wasm_signer_worker\.js)['"]/g;
const offenders = [];

for (const absFile of walkJsFiles(distEsmRoot)) {
  const code = fs.readFileSync(absFile, 'utf8');
  if (!code.includes('wasm/near_signer/pkg/wasm_signer_worker.js')) continue;

  let match;
  while ((match = importRe.exec(code))) {
    const spec = match[1];

    if (!spec.startsWith('.')) {
      offenders.push({
        file: absFile,
        spec,
        reason: 'import must be relative (starts with ".")',
      });
      continue;
    }

    const resolvedAbs = path.resolve(path.dirname(absFile), spec);
    if (!fs.existsSync(resolvedAbs)) {
      offenders.push({
        file: absFile,
        spec,
        reason: `resolved path does not exist: ${resolvedAbs}`,
      });
      continue;
    }

    const resolvedReal = fs.realpathSync(resolvedAbs);
    if (resolvedReal !== targetReal) {
      offenders.push({
        file: absFile,
        spec,
        reason: `resolved to unexpected file: ${resolvedReal}`,
      });
    }
  }
}

if (offenders.length) {
  console.error('[assert-near-signer-wasm-imports] Invalid NEAR wasm import specifiers in dist/esm:');
  for (const o of offenders.slice(0, 40)) {
    console.error(`  - ${path.relative(sdkRoot, o.file)}: "${o.spec}" (${o.reason})`);
  }
  if (offenders.length > 40) console.error(`  ...and ${offenders.length - 40} more`);
  process.exit(1);
}

console.log('[assert-near-signer-wasm-imports] OK: all NEAR wasm imports resolve within dist/esm');

