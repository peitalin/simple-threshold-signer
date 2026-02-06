# Relay Server

NEAR relay server that creates accounts on behalf of users, where the relayer pays gas fees.

## Features

- **Direct Account Creation**: Create NEAR accounts using relay server authority
- **Custom Funding**: Configurable initial balance for new accounts
- **Transaction Queuing**: Prevents nonce conflicts
- **Simple JSON API**: Easy integration

## API

### Health endpoints

- `GET /healthz` — basic server health + feature configuration hints (fast; no external dependency checks)
- `GET /readyz` — readiness check for configured dependencies (zk-email prover when configured)

### `POST /create_account_and_register_user`
Atomically create a NEAR account and register a WebAuthn authenticator in relay storage (contract-free).

- Request body (abridged): `{ new_account_id, new_public_key, device_number?, rp_id, webauthn_registration, authenticator_options? }`
- Response: `{ success, transactionHash?, error?, message? }`

This route is consumed internally by the SDK’s registration flows.

### Sessions (`POST /auth/passkey/options` → `POST /auth/passkey/verify`)

Verifies a standard WebAuthn assertion (contract-free; relay-stored authenticators + counter persistence) and issues a session.

- Step 1 (options): `POST /auth/passkey/options` with `{ user_id, rp_id, ttl_ms? }` → `{ challengeId, challengeB64u }`
- Step 2 (verify): `POST /auth/passkey/verify` with:
  ```json
  { "sessionKind": "jwt" | "cookie", "challengeId": "<id>", "webauthn_authentication": { /* assertion */ } }
  ```
- Response:
  - When `sessionKind` is `jwt`: `{ ok, verified, jwt }`.
  - When `sessionKind` is `cookie`: sets `Set-Cookie: w3a_session=<jwt>; HttpOnly; Secure; SameSite=Lax; Path=/` and omits `jwt` in body.

Notes
- The sample server mounts this route via the SDK router (`createRelayRouter(authService)`).
- For cookie sessions, CORS must allow credentials and specify explicit origins.
  The example config enables CORS with `origin: [EXPECTED_ORIGIN, EXPECTED_WALLET_ORIGIN]` and `credentials: true`.
  Your frontend must use `credentials: 'include'` with fetch.

### `POST /recover-email` (email recovery)

Receives a JSON `ForwardableEmailPayload` (including `raw` containing the full RFC822 message) and forwards it into `EmailRecoveryService.requestEmailRecovery`.

Production notes:
- This server is the HTTP sink; you still need an email ingress (inbound email provider/webhook or your own MTA pipeline) to receive SMTP and then `POST` here.
- Emails can be large; this example uses `express.json({ limit: '5mb' })`.

## Configuration

Create `.env` file:
```bash
RELAYER_ACCOUNT_ID=relayer.testnet
RELAYER_PRIVATE_KEY=ed25519:...
NEAR_NETWORK_ID=testnet
NEAR_RPC_URL=https://rpc.testnet.near.org
PORT=3001
EXPECTED_ORIGIN=http://localhost:3000
# If you serve from multiple origins, set EXPECTED_WALLET_ORIGIN as well
# EXPECTED_WALLET_ORIGIN=http://localhost:4173

# Optional: zk-email prover base URL (used when explicitMode='zk-email' or email body marker is 'zk-email')
# ZK_EMAIL_PROVER_BASE_URL=http://127.0.0.1:5588
# ZK_EMAIL_PROVER_TIMEOUT_MS=60000
```

## Development

### Persistence (Postgres / Redis / Upstash)

The relay stores WebAuthn authenticators (credential public keys + counters) and credential bindings privately (no on-chain verifier). By default the example relay uses **in-memory** stores, which means:
- credentials are lost on restart
- multi-instance deployments will intermittently fail (“Credential is not registered for user”)

For local dev, prefer Postgres (durable; also persists threshold session/auth KV):

```bash
# from examples/relay-server
pnpm run postgres:up
```

Then in your relay `.env`:

```bash
POSTGRES_URL=postgres://tatchi:tatchi@127.0.0.1:5432/tatchi
```

Alternatively, run Redis and set `REDIS_URL`:

```bash
# from examples/relay-server
docker compose -f docker-compose.redis.yml up -d
```

Then in your relay `.env`:

```bash
# Node-only TCP Redis
REDIS_URL=redis://127.0.0.1:6379
```

For production/serverless, prefer Upstash REST:
- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`

### Run the Server

```bash
pnpm install
pnpm run dev    # Development server with auto-reload
pnpm run build  # Build for production
pnpm start      # Production server
```
