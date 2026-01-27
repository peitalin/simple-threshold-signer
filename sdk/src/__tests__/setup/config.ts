import type { PasskeyTestConfig } from './types';

const FRONTEND_URL =
  String(process.env.W3A_TEST_FRONTEND_URL || '').trim()
  || ((process.env.NO_CADDY === '1' || process.env.CI === '1')
    ? 'http://localhost:5174'
    : 'https://example.localhost');

// In tests we default the RP ID to the wallet-origin base domain. This matches the
// default `iframeWallet.rpIdOverride` (example.localhost) so WebAuthn rpIdHash checks
// stay consistent across app + wallet origins (wallet.example.localhost).
const RP_ID = String(process.env.W3A_TEST_RP_ID || '').trim() || 'example.localhost';

export const DEFAULT_TEST_CONFIG: PasskeyTestConfig = {
  frontendUrl: FRONTEND_URL,
  nearNetwork: 'testnet',
  nearRpcUrl: 'https://test.rpc.fastnear.com',
  contractId: 'w3a-v1.testnet',
  relayerAccount: 'w3a-v1.testnet',
  rpId: RP_ID,
  useRelayer: true,
  relayer: {
    url: 'https://relay-server.localhost',
  },
  testReceiverAccountId: 'w3a-v1.testnet',
};
