---
title: Next Steps
---

# Next Steps: Register, Auto-Provision, Sign NEAR/Tempo/EVM

After [installation](./installation.md), the fastest path is:

1. Register a passkey account.
2. Auto-provision threshold signers for all chains.
3. Sign one transaction per chain (NEAR, Tempo, EVM).

## 1. Register and Auto-Provision Threshold Signers

In this setup:

- NEAR threshold signer is created during registration (`signerMode: threshold-signer`).
- Tempo + EVM threshold signers are created immediately after registration via `bootstrapThresholdEcdsaSession()`.

```tsx
import { useState } from 'react'
import { useTatchi } from '@tatchi-xyz/sdk/react'

type KeyRef = {
  tempo: unknown | null
  evm: unknown | null
}

const THRESHOLD_TTL_MS = 30 * 60 * 1000
const THRESHOLD_REMAINING_USES = 12

export function RegisterAndProvision() {
  const { registerPasskey, tatchi } = useTatchi()
  const [accountId, setAccountId] = useState<string | null>(null)
  const [keyRefs, setKeyRefs] = useState<KeyRef>({ tempo: null, evm: null })

  async function onRegister(): Promise<void> {
    const id = Date.now()
    const nextAccountId = `tatchi-test-${id}.${tatchi.configs.contractId}`

    const result = await registerPasskey(nextAccountId, {
      onEvent: (event) => console.log('registration event:', event),
    })
    if (!result.success || !result.nearAccountId) return

    setAccountId(result.nearAccountId)

    const [tempo, evm] = await Promise.all([
      tatchi.bootstrapThresholdEcdsaSession({
        nearAccountId: result.nearAccountId,
        options: {
          chain: 'tempo',
          ttlMs: THRESHOLD_TTL_MS,
          remainingUses: THRESHOLD_REMAINING_USES,
        },
      }),
      tatchi.bootstrapThresholdEcdsaSession({
        nearAccountId: result.nearAccountId,
        options: {
          chain: 'evm',
          ttlMs: THRESHOLD_TTL_MS,
          remainingUses: THRESHOLD_REMAINING_USES,
        },
      }),
    ])

    setKeyRefs({
      tempo: tempo.thresholdEcdsaKeyRef,
      evm: evm.thresholdEcdsaKeyRef,
    })
  }

  return (
    <div>
      <button onClick={onRegister}>Register Account</button>
      {accountId ? <p>account: {accountId}</p> : null}
      <p>tempo signer: {keyRefs.tempo ? 'ready' : 'pending'}</p>
      <p>evm signer: {keyRefs.evm ? 'ready' : 'pending'}</p>
    </div>
  )
}
```

## 2. Login and Create a Warm Signing Session

```tsx
import { useTatchi } from '@tatchi-xyz/sdk/react'

export function LoginButton(props: { nearAccountId: string }) {
  const { loginAndCreateSession } = useTatchi()

  async function onLogin(): Promise<void> {
    await loginAndCreateSession(props.nearAccountId, {
      signingSession: {
        ttlMs: 5 * 60 * 1000,
        remainingUses: 5,
      },
    })
  }

  return <button onClick={onLogin}>Log In</button>
}
```

## 3. Sign a NEAR Transaction (Threshold Ed25519)

```tsx
import { ActionType, useTatchi } from '@tatchi-xyz/sdk/react'

export function SignNear(props: { nearAccountId: string }) {
  const { tatchi } = useTatchi()

  async function onSignNear(): Promise<void> {
    const signed = await tatchi.signTransactionsWithActions({
      nearAccountId: props.nearAccountId,
      transactions: [
        {
          receiverId: tatchi.configs.contractId,
          actions: [
            {
              type: ActionType.FunctionCall,
              methodName: 'set_greeting',
              args: { greeting: 'hello from threshold near' },
              gas: '30000000000000',
              deposit: '0',
            },
          ],
        },
      ],
    })
    console.log('near signed tx:', signed)
  }

  return <button onClick={onSignNear}>Sign NEAR Tx</button>
}
```

## 4. Sign a Tempo Transaction (Threshold secp256k1)

```tsx
import { useTatchi } from '@tatchi-xyz/sdk/react'

export function SignTempo(props: { nearAccountId: string; thresholdEcdsaKeyRef: any }) {
  const { tatchi } = useTatchi()

  async function onSignTempo(): Promise<void> {
    const signed = await tatchi.signTempoWithThresholdEcdsa({
      nearAccountId: props.nearAccountId,
      thresholdEcdsaKeyRef: props.thresholdEcdsaKeyRef,
      request: {
        chain: 'tempo',
        kind: 'tempoTransaction',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {
          chainId: 42431n,
          maxPriorityFeePerGas: 1n,
          maxFeePerGas: 2n,
          gasLimit: 21_000n,
          calls: [{ to: `0x${'11'.repeat(20)}`, value: 0n, input: '0x' }],
          accessList: [],
          nonceKey: 0n,
          nonce: 1n,
          validBefore: null,
          validAfter: null,
          feePayerSignature: { kind: 'none' },
          aaAuthorizationList: [],
        },
      },
    })
    console.log('tempo signed tx:', signed)
  }

  return <button onClick={onSignTempo}>Sign Tempo Tx</button>
}
```

## 5. Sign an EVM EIP-1559 Transaction (Threshold secp256k1)

```tsx
import { useTatchi } from '@tatchi-xyz/sdk/react'

export function SignEvm(props: { nearAccountId: string; thresholdEcdsaKeyRef: any }) {
  const { tatchi } = useTatchi()

  async function onSignEvm(): Promise<void> {
    const signed = await tatchi.signTempoWithThresholdEcdsa({
      nearAccountId: props.nearAccountId,
      thresholdEcdsaKeyRef: props.thresholdEcdsaKeyRef,
      request: {
        chain: 'tempo',
        kind: 'eip1559',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {
          chainId: 11155111n,
          nonce: 7n,
          maxPriorityFeePerGas: 1_500_000_000n,
          maxFeePerGas: 3_000_000_000n,
          gasLimit: 21_000n,
          to: `0x${'22'.repeat(20)}`,
          value: 12_345n,
          data: '0x',
          accessList: [],
        },
      },
    })
    console.log('evm signed tx:', signed)
  }

  return <button onClick={onSignEvm}>Sign EVM Tx</button>
}
```

## Recap

- Registration creates your NEAR threshold signer.
- Registration flow can immediately bootstrap Tempo + EVM threshold signers.
- With those key refs, you can sign:
  - NEAR transactions (`signTransactionsWithActions`)
  - Tempo transactions (`signTempoWithThresholdEcdsa`, `kind: 'tempoTransaction'`)
  - EVM EIP-1559 transactions (`signTempoWithThresholdEcdsa`, `kind: 'eip1559'`)

## Troubleshooting

- `threshold session expired` or `No cached threshold-ecdsa session token`
  - Re-bootstrap the chain signer with `bootstrapThresholdEcdsaSession({ chain: 'tempo' | 'evm' })`, then retry signing.
- Missing Tempo/EVM keyRef in memory after reload
  - Re-run provisioning for both chains and cache the returned `thresholdEcdsaKeyRef` values.
- Signing fails right after login due to session state
  - Run `loginAndCreateSession()` first, then sign again.
- Repeated failures on one chain only
  - Re-provision only that chain (`chain: 'tempo'` or `chain: 'evm'`) to refresh the threshold session/keyRef pair.

## Next Steps

- [React Recipes](/docs/getting-started/react-recipes): patterns for auth, sessions, and account UX.
- [Other Frameworks](./other-frameworks.md): Next.js, Vue, Svelte, Express.
- [Concepts](../concepts/index.md): security model, threshold signing, architecture.
