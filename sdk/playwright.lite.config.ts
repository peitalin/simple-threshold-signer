import { defineConfig } from '@playwright/test';
import base from './playwright.config';

/**
 * "Lite" test suite: focuses on the threshold-only / wallet-origin flows and avoids
 * local-signer + offline-export coverage (still supported in the full SDK suite).
 */
export default defineConfig({
  ...base,
  testIgnore: [
    ...(Array.isArray((base as any).testIgnore) ? ((base as any).testIgnore as string[]) : []),
    // Local-signer / offline-export (still supported, but excluded from lite validation)
    '**/e2e/offline-export.*.test.ts',
    '**/unit/offline-open.unit.test.ts',
    '**/unit/router.offline-open.unit.test.ts',
    '**/unit/offline_export_fallback.unit.test.ts',
    '**/unit/export_ui.routing.unit.test.ts',
    // This wallet-iframe suite exercises exportNearKeypairWithUI sticky behavior.
    '**/wallet-iframe/router.behavior.sticky.test.ts',
  ],
});

