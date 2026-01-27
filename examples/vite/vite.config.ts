import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig, loadEnv } from 'vite'
import { tatchiWallet } from '@tatchi-xyz/sdk/plugins/vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const workspaceRoot = fileURLToPath(new URL('../..', import.meta.url))
  const viteRoot = fileURLToPath(new URL('.', import.meta.url))
  const coepMode = (env.VITE_COEP_MODE === 'strict' ? 'strict' : 'off') as 'strict' | 'off'

  // Make VITE_* visible to Node-side dev plugins (tatchiHeaders uses process.env for ROR fetch).
  if (env.VITE_WEBAUTHN_CONTRACT_ID) process.env.VITE_WEBAUTHN_CONTRACT_ID = env.VITE_WEBAUTHN_CONTRACT_ID
  if (env.VITE_NEAR_RPC_URL) process.env.VITE_NEAR_RPC_URL = env.VITE_NEAR_RPC_URL
  if (env.VITE_ROR_METHOD) process.env.VITE_ROR_METHOD = env.VITE_ROR_METHOD

  return {
    clearScreen: false,
    logLevel: 'info',
    server: {
      port: 5174,
      host: 'localhost',
      strictPort: true,
      // Allow access via reverse-proxied hosts (Caddy)
      allowedHosts: [
        'example.localhost',
        'wallet.example.localhost',
        'relay-server.localhost',
        'relay-server2.localhost',
        'relay-server3.localhost',
        'zk-email-prover.localhost',
      ],
      open: false,
      fs: {
        allow: [workspaceRoot],
      },
    },
    plugins: [
      // Serve SDK + wallet-service (+ headers) from a single dev server. Caddy provides distinct
      // origins (example.localhost vs wallet.example.localhost) by host-based proxying.
      tatchiWallet({
        enableDebugRoutes: true,
        sdkBasePath: env.VITE_SDK_BASE_PATH || '/sdk',
        walletServicePath: env.VITE_WALLET_SERVICE_PATH || '/wallet-service',
        walletOrigin: env.VITE_WALLET_ORIGIN || 'https://wallet.example.localhost',
        emitHeaders: false,
        coepMode,
      }),
    ],
    build: {
      rollupOptions: {
        input: {
          index: path.resolve(viteRoot, 'index.html'),
          demo: path.resolve(viteRoot, 'demo.html'),
        },
      },
    },
    define: {
      global: 'globalThis',
      'process.env': {},
    },
  }
})
