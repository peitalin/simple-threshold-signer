// Centralized build configuration
// This file defines all paths used across the build system

export const BUILD_PATHS = {
  // Build output directories
  BUILD: {
    ROOT: 'dist',
    WORKERS: 'dist/workers',
    ESM: 'dist/esm',
    TYPES: 'dist/types',
  },

  // Source directories
  SOURCE: {
    ROOT: '../client/src',
    CORE: '../client/src/core',
    WASM_SIGNER: '../wasm/near_signer',
    WASM_ETH_SIGNER: '../wasm/eth_signer',
    WASM_TEMPO_SIGNER: '../wasm/tempo_signer',
    CRITICAL_DIRS: [
      '../client/src/core',
      '../client/src/react',
      '../client/src/utils',
      '../server/src',
      '../shared/src',
      '../wasm/near_signer',
      '../wasm/eth_signer',
      '../wasm/tempo_signer',
    ],
  },

  // Frontend deployment paths
  FRONTEND: {
    ROOT: '../examples/vite/public',
    SDK: '../examples/vite/public/sdk',
    WORKERS: '../examples/vite/public/sdk/workers',
  },

  // Runtime paths (used by workers and tests)
  RUNTIME: {
    SDK_BASE: '/sdk',
    WORKERS_BASE: '/sdk/workers',
    SECURE_CONFIRM_WORKER: '/sdk/workers/passkey-confirm.worker.js',
    SIGNER_WORKER: '/sdk/workers/near-signer.worker.js',
  },

  // Worker file names
  WORKERS: {
    SECURE_CONFIRM: 'passkey-confirm.worker.js',
    SIGNER: 'near-signer.worker.js',
    WASM_SIGNER_JS: 'wasm_signer_worker.js',
    WASM_SIGNER_WASM: 'wasm_signer_worker_bg.wasm',
  },

  // Test worker file paths (for test files)
  TEST_WORKERS: {
    SECURE_CONFIRM: '/sdk/workers/passkey-confirm.worker.js',
    SIGNER: '/sdk/workers/near-signer.worker.js',
    WASM_SIGNER_JS: '/sdk/workers/wasm_signer_worker.js',
    WASM_SIGNER_WASM: '/sdk/workers/wasm_signer_worker_bg.wasm',
  },
} as const;

// Helper functions
export const getWorkerPath = (workerName: string): string =>
  `${BUILD_PATHS.BUILD.WORKERS}/${workerName}`;
export const getRuntimeWorkerPath = (workerName: string): string =>
  `${BUILD_PATHS.RUNTIME.WORKERS_BASE}/${workerName}`;
export const getFrontendWorkerPath = (workerName: string): string =>
  `${BUILD_PATHS.FRONTEND.WORKERS}/${workerName}`;

// Default export for easier importing
export default BUILD_PATHS;
