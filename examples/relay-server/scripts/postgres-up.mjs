#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import net from 'node:net';

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

async function waitForPort({ host, port, timeoutMs }) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await new Promise((resolve) => {
      const socket = net.createConnection({ host, port });
      socket.once('connect', () => {
        socket.destroy();
        resolve(true);
      });
      socket.once('error', () => {
        socket.destroy();
        resolve(false);
      });
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`Timed out waiting for ${host}:${port} to accept connections`);
}

async function main() {
  const relayRoot = path.dirname(fileURLToPath(import.meta.url));
  const cwd = path.resolve(relayRoot, '..');

  try {
    await run('docker', ['compose', '-f', 'docker-compose.postgres.yml', 'up', '-d'], { cwd });
  } catch (err) {
    console.error('[postgres-up] Failed to start Postgres via docker compose.');
    console.error('[postgres-up] Ensure Docker Desktop is installed/running, then retry.');
    throw err;
  }

  await waitForPort({ host: '127.0.0.1', port: 5432, timeoutMs: 30_000 });
  console.log('[postgres-up] Postgres is accepting connections on 127.0.0.1:5432');
}

main().catch((err) => {
  console.error('[postgres-up] fatal:', err);
  process.exit(1);
});

