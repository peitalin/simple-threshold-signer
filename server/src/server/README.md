# Server Package

AuthService provides the server‑side pieces for account creation and WebAuthn verification. Session handling is optional and pluggable — pass a SessionService (or compatible adapter) into the routers. The SDK itself does not bundle a JWT library.

## Quick Start (Express)

```ts
import express from 'express';
import cors from 'cors';
import { AuthService, SessionService } from '@tatchi-xyz/sdk/server';
import { createRelayRouter } from '@tatchi-xyz/sdk/server/router/express';
import jwt from 'jsonwebtoken';

const service = new AuthService({
  relayerAccountId: process.env.RELAYER_ACCOUNT_ID!,
  relayerPrivateKey: process.env.RELAYER_PRIVATE_KEY!,
  webAuthnContractId: process.env.WEBAUTHN_CONTRACT_ID || 'w3a-v1.testnet',
  nearRpcUrl: process.env.NEAR_RPC_URL || 'https://rpc.testnet.near.org',
  networkId: process.env.NETWORK_ID || 'testnet'
});

const session = new SessionService({
  jwt: {
    signToken: ({ payload }) => {
      // If payload.exp is supplied (e.g., threshold session tokens), do not override it with `expiresIn`.
      const hasExp = typeof (payload as any).exp === 'number' && Number.isFinite((payload as any).exp);
      return jwt.sign(payload as any, process.env.JWT_SECRET || 'dev-insecure', {
        algorithm: 'HS256',
        issuer: process.env.JWT_ISSUER || 'relay',
        audience: process.env.JWT_AUDIENCE || 'app',
        ...(hasExp ? {} : { expiresIn: Number(process.env.JWT_EXPIRES_SEC || 24 * 60 * 60) }),
      });
    },
    verifyToken: async (token: string) => {
      try { const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-insecure') as any; return { valid: true, payload }; }
      catch { return { valid: false }; }
    }
  },
  // Minimal cookie config (defaults to HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=24h)
  cookie: { name: 'w3a_session' }
});

const app = express();
app.use(express.json());
app.use(cors({ origin: [process.env.EXPECTED_ORIGIN!, process.env.EXPECTED_WALLET_ORIGIN!].filter(Boolean), credentials: true }));
app.use('/', createRelayRouter(service, { healthz: true, readyz: true, session }));
app.listen(3000);
```

## Quick Start (Cloudflare Workers)

```ts
import { AuthService, SessionService } from '@tatchi-xyz/sdk/server';
import { createCloudflareRouter } from '@tatchi-xyz/sdk/server/router/cloudflare';
import signerWasm from '@tatchi-xyz/sdk/server/wasm/signer';
import jwt from 'jsonwebtoken';

const service = new AuthService({
  relayerAccountId: env.RELAYER_ACCOUNT_ID,
  relayerPrivateKey: env.RELAYER_PRIVATE_KEY,
  webAuthnContractId: env.WEBAUTHN_CONTRACT_ID,
  nearRpcUrl: env.NEAR_RPC_URL,
  networkId: env.NETWORK_ID || 'testnet',
  signerWasm: { moduleOrPath: signerWasm }
});

const session = new SessionService({
  jwt: {
    signToken: ({ payload }) => jwt.sign(payload as any, env.JWT_SECRET || 'dev-insecure', { algorithm: 'HS256' }),
    verifyToken: async (token: string) => { try { return { valid: true, payload: jwt.verify(token, env.JWT_SECRET || 'dev-insecure') }; } catch { return { valid: false }; } }
  },
  cookie: { name: 'w3a_session' }
});

export default {
  async fetch(request: Request, env: any, ctx: any) {
    const router = createCloudflareRouter(service, { healthz: true, readyz: true, corsOrigins: [env.EXPECTED_ORIGIN, env.EXPECTED_WALLET_ORIGIN].filter(Boolean), session });
    return router(request, env, ctx);
  }
}
```

## Routes exposed by the routers

- POST `/create_account_and_register_user` — atomic account creation + passkey registration (contract-free). Body:
  - `{ new_account_id, new_public_key, device_number?, rp_id, webauthn_registration, expected_origin?, authenticator_options? }`
  - Note: `new_account_id` must be a subaccount of `relayerAccountId` (`RELAYER_ACCOUNT_ID`) because the relayer signs the `CreateAccount` transaction.
- POST `/auth/passkey/options` — mint a server-side WebAuthn login challenge (replay-protected). Body:
  - `{ user_id, rp_id, ttl_ms? }` → returns `{ challengeId, challengeB64u, expiresAtMs }`
- POST `/auth/passkey/verify` — WebAuthn verification + optional session issuance (contract-free). Body:
  - `{ sessionKind: 'jwt' | 'cookie', challengeId, webauthn_authentication }`
  - The relay verifies signatures using its private authenticator store and persists counters.
  - `sessionKind='jwt'` → JSON returns `{ jwt }`; `sessionKind='cookie'` → sets `Set-Cookie` (HttpOnly) and omits `jwt` in body.
- POST `/recover-email` — email-based account recovery (TEE/DKIM by default; zk-email when `explicitMode: 'zk-email'` or the email body includes a `zk-email` marker)
- GET `/healthz` — basic server health + feature configuration hints (optional, enabled via router config)
- GET `/readyz` — readiness check for configured dependencies (optional, enabled via router config)
- GET `/session/auth` — returns `{ authenticated, claims? }` based on Authorization: Bearer or cookie
- POST `/session/logout` — clears the session cookie
- GET `/.well-known/webauthn` — Related Origin Requests manifest (wallet-scoped credentials)

## Sessions

You have two integration styles:

1) Provide a SessionService (hook‑first) or compatible adapter
- Supply `signToken` and `verifyToken` using your preferred JWT library (e.g., jsonwebtoken).
- Optionally provide cookie hooks to customize headers if using cookie mode.

Cookie hooks (optional)
```ts
const session = new SessionService({
  jwt: { /* signToken/verifyToken as above */ },
  cookie: {
    name: 'w3a_session',
    // Customize Set-Cookie attributes (e.g., cross-site):
    buildSetHeader: (token) => [
      `w3a_session=${token}`,
      'Path=/',
      'HttpOnly',
      'Secure',
      'SameSite=None',
      'Domain=.example.localhost',
      'Max-Age=86400'
    ].join('; '),
    buildClearHeader: () => [
      'w3a_session=',
      'Path=/',
      'HttpOnly',
      'Secure',
      'SameSite=None',
      'Domain=.example.localhost',
      'Max-Age=0',
      'Expires=Thu, 01 Jan 1970 00:00:00 GMT'
    ].join('; '),
    // Optional: custom extraction from headers (Bearer or Cookie)
    extractToken: (headers, cookieName) => {
      const auth = (headers['authorization'] || headers['Authorization']) as string | undefined;
      if (auth && /^Bearer\s+/.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
      const cookie = (headers['cookie'] || headers['Cookie']) as string | undefined;
      if (!cookie) return null;
      for (const part of cookie.split(';')) {
        const [k, v] = part.split('=');
        if (k && k.trim() === cookieName) return (v || '').trim();
      }
      return null;
    }
  }
});
```

For cookies, configure CORS with explicit origins and `credentials: true`.

Default behavior
- No session is minted by default. The client must opt‑in by calling `loginAndCreateSession(..., { session: { kind: 'jwt' | 'cookie', relayUrl?, route? }})`.
- On the server, sessions are only active if you provide a SessionService (or compatible adapter) to the router options.

Configurable session endpoints
- Express adaptor: `createRelayRouter(service, { session, sessionRoutes })` (defaults to `/session/auth` and `/session/logout`).
- Cloudflare adaptor: `createCloudflareRouter(service, { session, sessionRoutes, corsOrigins })` (same defaults).

Cloudflare CORS note
- The Cloudflare router will only set `Access-Control-Allow-Credentials: true` when echoing a specific Origin. If `corsOrigins` is `'*'`, credentials are not advertised (as required by Fetch/CORS rules). Use explicit origins when using cookie sessions.

## Config (required)

```bash
RELAYER_ACCOUNT_ID=relayer.testnet
RELAYER_PRIVATE_KEY=ed25519:...
WEBAUTHN_CONTRACT_ID=w3a-v1.testnet
NEAR_RPC_URL=https://rpc.testnet.near.org
NETWORK_ID=testnet
```

Optional session vars (examples use these):

```bash
JWT_SECRET=change-me
JWT_ISSUER=relay
JWT_AUDIENCE=your-app
JWT_EXPIRES_SEC=86400
SESSION_COOKIE_NAME=w3a_session

# Optional: override session route paths
# Session routes are configured in code via router options.
```
