#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: 'inherit', ...opts });
    p.on('error', reject);
    p.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${cmd} ${args.join(' ')} exited with code ${code ?? 'unknown'}`));
    });
  });
}

async function main() {
  const relayRoot = path.dirname(fileURLToPath(import.meta.url));
  const cwd = path.resolve(relayRoot, '..');
  await run('docker', ['compose', '-f', 'docker-compose.postgres.yml', 'down'], { cwd });
}

main().catch((err) => {
  console.error('[postgres-down] fatal:', err);
  process.exit(1);
});

