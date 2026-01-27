---
title: Relay Server Deployment
---

# Relay Server Deployment

The relay server is a backend service that enables account creation and coordinates threshold signing and WebAuthn session authorization. This guide covers deployment to both Node.js/Express and Cloudflare Workers.

**Note**: NEAR account creation still benefits from a relay server (gas + UX). Threshold signing also requires a relay to act as the cosigner. Relay servers can be setup by anyone.


## When You Need a Relay Server

The relay server handles these main responsibilities:

### 1. Account Creation

Creates NEAR accounts atomically with passkey registration. Without a relay, users would need to:
1. Create a NEAR account separately
2. Fund it
3. Then register their passkey

The relay combines these into a single operation with a better UX.

### 2. Threshold Signing + Sessions

Coordinates 2‑party threshold signing (client ↔ relay) via `/threshold-ed25519/*` endpoints. Optionally, the relay can mint short‑lived session tokens after verifying a standard WebAuthn assertion (to avoid per-sign prompts).

**Can you skip the relay?** Only if you are not using threshold signing and you don't need atomic account creation.



## Deployment Options

Choose based on your infrastructure:

| Platform | Best For | Key Benefits |
|----------|----------|--------------|
| **Express/Node.js** | Traditional hosting, existing Node infrastructure | Familiar stack, filesystem access, easy local dev |
| **Cloudflare Workers** | Serverless, global edge deployment | Auto-scaling, low latency, no server management |

Both platforms expose the same API and work identically from the client's perspective.



## Option 1: Express/Node.js

### Project Setup

**Location**: `examples/relay-server/`

**Structure**:
```
relay-server/
├── src/
│   └── index.ts          # Express server entry point
├── .env                  # Configuration
└── package.json
```

### Implementation

```typescript
import express from 'express'
import cors from 'cors'
import { AuthService } from '@tatchi-xyz/sdk/server'
import { createRelayRouter } from '@tatchi-xyz/sdk/server/router/express'

const app = express()
app.use(express.json())
app.use(cors({
  origin: [
    process.env.EXPECTED_ORIGIN,
    process.env.EXPECTED_WALLET_ORIGIN
  ],
  credentials: true
}))

// Initialize the authentication service
const service = new AuthService({
  relayerAccountId: process.env.RELAYER_ACCOUNT_ID!,
  relayerPrivateKey: process.env.RELAYER_PRIVATE_KEY!,
  webAuthnContractId: process.env.WEBAUTHN_CONTRACT_ID || 'w3a-v1.testnet',
  nearRpcUrl: process.env.NEAR_RPC_URL || 'https://test.rpc.fastnear.com',
  networkId: 'testnet',
  accountInitialBalance: '30000000000000000000000', // 0.03 NEAR
  createAccountAndRegisterGas: '85000000000000',
})

// Mount relay endpoints
app.use('/', createRelayRouter(service, { healthz: true }))
app.listen(3000, () => {
  console.log('Relay server listening on port 3000')
})
```

### Configuration

Create a `.env` file:

```bash
# NEAR Configuration
RELAYER_ACCOUNT_ID=relayer.testnet
RELAYER_PRIVATE_KEY=ed25519:...
NEAR_RPC_URL=https://test.rpc.fastnear.com
WEBAUTHN_CONTRACT_ID=w3a-v1.testnet

# CORS
EXPECTED_ORIGIN=http://localhost:5173
EXPECTED_WALLET_ORIGIN=https://wallet.example.localhost

# Optional (threshold signing)
THRESHOLD_ED25519_MASTER_SECRET_B64U=...
```

### Running Locally

```bash
cd examples/relay-server
pnpm install
pnpm dev
```



## Option 2: Cloudflare Workers

### Why Cloudflare Workers?

- **Global edge network**: Serve requests from locations close to users
- **Auto-scaling**: Handle traffic spikes without configuration
- **No servers**: Pay only for requests, not idle time
- **WASM support**: Run cryptographic operations at near-native speed

### Project Setup

**Location**: `examples/relay-cloudflare-worker/`

**Structure**:
```
relay-cloudflare-worker/
├── src/
│   └── worker.ts         # Worker entry point
├── wrangler.toml         # Cloudflare configuration
└── package.json
```

### Implementation

The key difference from Express is WASM module handling:

```typescript
import { AuthService } from '@tatchi-xyz/sdk/server'
import { createCloudflareRouter } from '@tatchi-xyz/sdk/server/router/cloudflare'

// Import WASM modules directly (Workers can't use import.meta.url)
import signerWasmModule from '@tatchi-xyz/sdk/server/wasm/signer'

function buildService(env: any) {
  return new AuthService({
    relayerAccountId: env.RELAYER_ACCOUNT_ID,
    relayerPrivateKey: env.RELAYER_PRIVATE_KEY,
    webAuthnContractId: env.WEBAUTHN_CONTRACT_ID,
    nearRpcUrl: env.NEAR_RPC_URL,
    networkId: env.NETWORK_ID || 'testnet',
    accountInitialBalance: env.ACCOUNT_INITIAL_BALANCE,
    createAccountAndRegisterGas: env.CREATE_ACCOUNT_AND_REGISTER_GAS,

  // Pass WASM modules directly
  signerWasm: { moduleOrPath: signerWasmModule },
})
}

export default {
  async fetch(request, env, ctx) {
    const service = buildService(env)
    const router = createCloudflareRouter(service, {
      corsOrigins: [env.EXPECTED_ORIGIN, env.EXPECTED_WALLET_ORIGIN].filter(Boolean),
      healthz: true,
      readyz: true,
    })
    return router(request, env, ctx)
  },
}
```

### WASM Bundling Configuration

Cloudflare Workers require explicit WASM bundling. Update `wrangler.toml`:

```toml
name = "w3a-relay-prod"
main = "src/worker.ts"
compatibility_date = "2024-09-24"
compatibility_flags = ["nodejs_compat"]

# Bundle WASM modules
[[rules]]
type = "CompiledWasm"
globs = ["**/*.wasm"]
fallthrough = true

[triggers]
crons = []

# Production worker (separate Worker name + CORS allowlist)
[env.production]
name = "w3a-relay-prod"

[env.production.vars]
RELAYER_ACCOUNT_ID = "w3a-relayer.testnet"
NEAR_RPC_URL = "https://test.rpc.fastnear.com"
NETWORK_ID = "testnet"
WEBAUTHN_CONTRACT_ID = "w3a-v1.testnet"
ACCOUNT_INITIAL_BALANCE = "40000000000000000000000" # 0.04 NEAR
CREATE_ACCOUNT_AND_REGISTER_GAS = "85000000000000"  # 85 TGas
RELAYER_URL = "https://relay.example.com"
EXPECTED_ORIGIN = "https://app.example.com"
EXPECTED_WALLET_ORIGIN = "https://wallet.example.com"

# Staging worker (separate Worker name + tighter CORS allowlist)
[env.staging]
name = "w3a-relay-staging"

[env.staging.vars]
RELAYER_ACCOUNT_ID = "w3a-relayer.testnet"
NEAR_RPC_URL = "https://test.rpc.fastnear.com"
NETWORK_ID = "testnet"
WEBAUTHN_CONTRACT_ID = "w3a-v1.testnet"
ACCOUNT_INITIAL_BALANCE = "40000000000000000000000" # 0.04 NEAR
CREATE_ACCOUNT_AND_REGISTER_GAS = "85000000000000"  # 85 TGas
RELAYER_URL = "https://relay-staging.example.com"
EXPECTED_ORIGIN = "https://staging.app.example.com"
EXPECTED_WALLET_ORIGIN = "https://wallet-staging.example.com"
```

### Managing Secrets

Secrets are never committed to `wrangler.toml`. Use the CLI:

```bash
# Authenticate once
wrangler login

# Set secrets for production
wrangler secret put RELAYER_PRIVATE_KEY --env production
# Optional (threshold signing)
wrangler secret put THRESHOLD_ED25519_MASTER_SECRET_B64U --env production

# Set secrets for staging
wrangler secret put RELAYER_PRIVATE_KEY --env staging
# Optional (threshold signing)
wrangler secret put THRESHOLD_ED25519_MASTER_SECRET_B64U --env staging
```

### Deployment

```bash
cd examples/relay-cloudflare-worker
pnpm install
wrangler deploy --env staging
wrangler deploy --env production
```

Your relay is now live at `https://your-worker.your-subdomain.workers.dev`.

### Local Development

Test against the real Cloudflare runtime:

```bash
# Run against Cloudflare's edge (uses real WASM runtime)
wrangler dev --remote

# Watch logs
wrangler tail
```

**Why `--remote`?** The local emulator doesn't perfectly match Cloudflare's WASM environment. Testing remotely catches issues early.



## API Reference

Both platforms expose identical endpoints used by the SDK:

### Create Account + Register

**`POST /create_account_and_register_user`**

Atomically creates a NEAR account and registers the passkey in a single blockchain transaction.

**Request**:
```json
{
  "new_account_id": "alice.testnet",
  "new_public_key": "ed25519:...",
  "webauthn_registration": {
    "attestation_object": "...",
    "client_data_json": "...",
    "prf_outputs": "..."
  },
  "deterministic_vrf_public_key": "ed25519:...",
  "vrf_data": {
    "salt": "...",
    "iterations": 100000
  }
}
```

**Response**:
```json
{
  "success": true,
  "transactionHash": "ABC123..."
}
```

**Errors**:
- `409`: Account already exists
- `400`: Invalid passkey data
- `500`: Blockchain transaction failed

### Health Check

**`GET /healthz`** (optional, enabled via router config)

Returns `200 OK` if the service is healthy.



## cURL Examples

Test your relay manually:

```bash
# Check health
curl https://relay.example.com/healthz
```



## Security Considerations

### CORS Configuration

Be explicit about allowed origins:

```typescript
// Good: Specific origins
cors({ origin: ['https://app.example.com', 'https://wallet.example.com'] })

// Bad: Accept all origins
cors({ origin: '*' })  // ← Don't do this in production
```

### Secret Management

**Express**:
- Use `.env` files (never commit them!)
- For production: Use secret managers (AWS Secrets Manager, HashiCorp Vault)
- Rotate `RELAYER_PRIVATE_KEY` periodically

**Cloudflare**:
- Always use `wrangler secret put` for sensitive values
- Secrets are encrypted at rest and in transit
- Use separate Workers for staging/production



## Troubleshooting

### Common Issues

#### "Invalid URL string" (Cloudflare only)

**Cause**: Worker tried to use `import.meta.url` to load WASM, which doesn't work in the Workers runtime.

**Fix**:
1. Import WASM modules directly: `import signerWasmModule from '@tatchi-xyz/sdk/server/wasm/signer'`
2. Pass via config: `signerWasm: { moduleOrPath: signerWasmModule }`
3. Ensure `wrangler.toml` has the WASM bundling rule

#### CORS Errors

**Symptoms**: Browser shows "blocked by CORS policy" in console.

**Fix**:
- Express: Verify `cors()` middleware includes the client origin
- Cloudflare: Set `EXPECTED_ORIGIN` and `EXPECTED_WALLET_ORIGIN` in `wrangler.toml`
- Check browser DevTools → Network → Response Headers for `Access-Control-Allow-Origin`

#### Account Creation Fails with "insufficient balance"

**Cause**: Relay account doesn't have enough NEAR to fund new accounts.

**Fix**:
1. Check relayer balance: `near state relayer.testnet`
2. Fund it: `near send your-account.testnet relayer.testnet 10`
3. Verify `accountInitialBalance` in config is reasonable (0.03 NEAR is typical)

### Debugging Tips

**Express**:
```typescript
// Add request logging
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`, req.body)
  next()
})
```

**Cloudflare**:
```bash
# Live tail logs
wrangler tail

# Filtered logs
wrangler tail --status error
```



## Next Steps

- **Configure the SDK**: Point your client at the relay URL
- **Set up monitoring**: Track account creation rate, error rates, key rotation events
- **Configure CI/CD**: See [Cloudflare + GitHub Actions](/docs/guides/cloudflare-github-actions) for automated deployments
- **Review security**: Read the [Security Model](/docs/concepts/security-model) to understand the full architecture
