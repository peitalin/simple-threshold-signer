import { defineConfig } from '@playwright/test';
import base from './playwright.config';

/**
 * "Lite" test suite: focuses on the threshold-only / wallet-origin flows and avoids
 * local-signer coverage.
 */
export default defineConfig({
  ...base,
  testIgnore: [
    ...(Array.isArray((base as any).testIgnore) ? ((base as any).testIgnore as string[]) : []),
    // Local-signer coverage (excluded from lite validation)
    // This wallet-iframe suite exercises exportNearKeypairWithUI sticky behavior.
    '**/wallet-iframe/router.behavior.sticky.test.ts',
  ],
});
