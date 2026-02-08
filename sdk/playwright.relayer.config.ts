import * as playwrightNs from '@playwright/test';

// Playwright is sometimes loaded via CJS↔ESM interop. Use a tolerant import shape.
const defineConfig =
  (playwrightNs as any).defineConfig || (playwrightNs as any).default?.defineConfig;
if (typeof defineConfig !== 'function') {
  throw new Error('Playwright relayer config failed to load defineConfig from @playwright/test');
}

export default defineConfig({
  // Keep path aliases consistent with the main suite.
  tsconfig: './tsconfig.playwright.json',
  // Don't transform wasm-bindgen outputs; Playwright's transpiler can break these ESM glue files.
  build: { external: ['wasm/**/pkg/**'] },
  testDir: '../tests',
  testMatch: [
    '**/relayer/**/*.test.ts',
  ],
  fullyParallel: false,
  retries: 0,
  workers: 1,
  timeout: 30_000,
  reporter: 'html',
});
