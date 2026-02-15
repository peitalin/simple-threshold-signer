import * as playwrightNs from '@playwright/test';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Playwright is sometimes loaded via CJS↔ESM interop. Use a tolerant import shape.
const defineConfig =
  (playwrightNs as any).defineConfig || (playwrightNs as any).default?.defineConfig;
const devices = (playwrightNs as any).devices || (playwrightNs as any).default?.devices || {};
if (typeof defineConfig !== 'function') {
  throw new Error('Playwright config failed to load defineConfig from @playwright/test');
}
// Default to NO_CADDY for tests unless explicitly enabled.
// Caddy's default HTTPS port (443) is privileged on many systems, which can
// cause test startup failures when running as a non-root user.
if (process.env.NO_CADDY == null && process.env.USE_CADDY == null) {
  process.env.NO_CADDY = '1';
}

function resolveDefaultFrontendUrlNoCaddy(): string {
  // If the caller explicitly overrides, respect it.
  const existing = String(process.env.W3A_TEST_FRONTEND_URL || '').trim();
  if (existing) return existing;

  // Prefer a stable default port, but avoid reusing an unrelated dev server
  // (common when another Vite app is running on 5174).
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const expectedSdkDistRoot = fs.realpathSync(path.resolve(path.join(__dirname, '../sdk/dist')));
    const script = `
      const fs = require('node:fs');
      const ports = [5174, 5180, 5175, 5181, 5190, 5191];
      const expected = process.argv[2];
      const timeoutMs = 250;

      async function classify(port) {
        const url = \`http://127.0.0.1:\${port}/__sdk-root\`;
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), timeoutMs);
        try {
          const res = await fetch(url, { signal: controller.signal });
          if (!res.ok) return { kind: 'in_use_wrong' };
          const text = String(await res.text()).trim();
          if (text && fs.existsSync(text)) {
            try {
              const real = fs.realpathSync(text);
              if (real === expected) return { kind: 'in_use_correct' };
            } catch {}
          }
          return { kind: 'in_use_wrong' };
        } catch (e) {
          return { kind: 'free' };
        } finally {
          clearTimeout(t);
        }
      }

      (async () => {
        for (const port of ports) {
          const r = await classify(port);
          if (r.kind === 'in_use_correct') {
            console.log(port);
            return;
          }
          if (r.kind === 'free') {
            console.log(port);
            return;
          }
        }
        console.log(5174);
      })();
    `;
    const chosenPortRaw = execFileSync(process.execPath, ['-e', script, expectedSdkDistRoot], {
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8',
    })
      .toString()
      .trim();
    const chosenPort = Number(chosenPortRaw);
    if (Number.isFinite(chosenPort) && chosenPort > 0) {
      const chosen = `http://127.0.0.1:${chosenPort}`;
      process.env.W3A_TEST_FRONTEND_URL = chosen;
      return chosen;
    }
  } catch {}

  const fallback = 'http://127.0.0.1:5174';
  process.env.W3A_TEST_FRONTEND_URL = fallback;
  return fallback;
}

// Ensure wallet dev CSP is strict during tests unless explicitly overridden.
// This allows tests to rely on strict CSP while preserving an escape hatch
// for local debugging (set VITE_WALLET_DEV_CSP=compatible).
if (process.env.VITE_WALLET_DEV_CSP == null) {
  process.env.VITE_WALLET_DEV_CSP = 'strict';
}

// Enable COEP during tests to exercise cross-origin isolation behavior.
// Default app behavior is COEP off to preserve browser extension compatibility.
if (process.env.VITE_COEP_MODE == null) {
  process.env.VITE_COEP_MODE = 'strict';
}

/**
 * @see https://playwright.dev/docs/test-configuration
 */
const USE_RELAY_SERVER = process.env.USE_RELAY_SERVER === '1' || process.env.USE_RELAY_SERVER === 'true';
const NO_CADDY = process.env.NO_CADDY === '1' || process.env.VITE_NO_CADDY === '1' || process.env.CI === '1';
const OVERRIDE_FRONTEND_URL = NO_CADDY ? resolveDefaultFrontendUrlNoCaddy() : String(process.env.W3A_TEST_FRONTEND_URL || '').trim();
const BASE_URL = OVERRIDE_FRONTEND_URL || (NO_CADDY ? 'http://127.0.0.1:5174' : 'https://example.localhost');
const DEV_SERVER_URL = (() => {
  if (OVERRIDE_FRONTEND_URL) {
    try {
      const u = new URL(OVERRIDE_FRONTEND_URL);
      u.hash = '';
      u.search = '';
      u.pathname = '/';
      return u.toString().replace(/\/$/, '');
    } catch {
      return OVERRIDE_FRONTEND_URL;
    }
  }
  return 'http://127.0.0.1:5174';
})();
const DEV_SERVER_PORT = (() => {
  try {
    const u = new URL(DEV_SERVER_URL);
    const raw = u.port || (u.protocol === 'https:' ? '443' : '80');
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : 5174;
  } catch {
    return 5174;
  }
})();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
try {
  process.env.W3A_REPO_ROOT = fs.realpathSync(path.resolve(path.join(__dirname, '..')));
} catch {}
try {
  process.env.W3A_SDK_DIST_ROOT = fs.realpathSync(path.resolve(path.join(__dirname, '../sdk/dist')));
} catch {}
function resolveExamplesFrontendDir(): string {
  // Prefer the historical examples/vite path when present, but fall back to the
  // current workspace frontend (examples/tatchi-docs) when it's the only one.
  const candidates = ['../examples/vite', '../examples/tatchi-docs'].map((p) => path.resolve(path.join(__dirname, p)));
  const existing = candidates.find((dir) => fs.existsSync(dir) && fs.existsSync(path.join(dir, 'package.json')));
  if (!existing) {
    throw new Error(`[playwright] missing frontend example; tried: ${candidates.join(', ')}`);
  }
  return existing;
}
const EXAMPLES_FRONTEND_DIR = resolveExamplesFrontendDir();

export default defineConfig({
  // Use a single tsconfig for all test imports so TS `paths` aliases resolve consistently.
  tsconfig: './tsconfig.playwright.json',
  // Don't transform wasm-bindgen outputs; Playwright's transpiler can break these ESM glue files.
  build: { external: ['wasm/**/pkg/**'] },
  testDir: '.',
  testMatch: [
    '**/e2e/**/*.test.ts',
    '**/unit/**/*.test.ts',
    // Include wallet-iframe + lit-components tests regardless of subfolder
    '**/wallet-iframe/**/*.test.ts',
    '**/lit-components/**/*.test.ts',
  ],
  fullyParallel: false,
  retries: 0,
  workers: 1, // Reduced to 1 to prevent parallel faucet requests and rate limiting
  // Increase default per-test timeout (Playwright default is 30s). Some
  // end-to-end flows (registration/login/action) can legitimately exceed 30s
  // under CI or when relay/network is slow.
  timeout: 60_000,
  reporter: 'html',
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: BASE_URL,
    /* Caddy serves self-signed certs for example.localhost */
    ignoreHTTPSErrors: true,
    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: 'on-first-retry',
    /* Enable verbose console logging for debugging */
    // video: 'retain-on-failure',
    // screenshot: 'only-on-failure',
  },

  /* Configure projects for major browsers */
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    // Note: WebAuthn Virtual Authenticator requires CDP which is only available in Chromium
    // Safari/WebKit tests would need different WebAuthn testing approach
  ],

  /* Run your local dev server(s) before starting the tests */
  webServer: {
    // If USE_RELAY_SERVER is set, start both servers with a relay health check
    command: USE_RELAY_SERVER
      ? 'node ./scripts/start-servers.mjs'
      : (NO_CADDY
        ? `pnpm -C "${EXAMPLES_FRONTEND_DIR}" exec vite --host 127.0.0.1 --port ${DEV_SERVER_PORT} --strictPort`
        : `pnpm -C "${EXAMPLES_FRONTEND_DIR}" dev`),
    url: DEV_SERVER_URL,
    reuseExistingServer: true,
    timeout: 60000, // Allow time for relay health check + build
    // Propagate strict CSP to the dev server process.
    env: {
      VITE_WALLET_DEV_CSP: process.env.VITE_WALLET_DEV_CSP ?? 'strict',
      VITE_COEP_MODE: process.env.VITE_COEP_MODE ?? 'strict',
    },
  },
});
