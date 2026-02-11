---
title: SecureConfirm WebAuthn
---

# SecureConfirm WebAuthn

The wallet pairs WebAuthn PRF with **verifiable random function (SecureConfirm)** challenges to gate every session on fresh chain data. WebAuthn proves user presence; the SecureConfirm proves freshness against NEAR block data. A dual-worker pipeline keeps PRF outputs and `secureconfirm_sk` in the SecureConfirm worker and only shares `WrapKeySeed + wrapKeySalt` with the signer worker.

- **Traditional WebAuthn** requires a server to generate challenges, verify signatures, and maintain session state.
- **In Web3Authn** the SecureConfirm worker generates challenges client-side, binds them to NEAR block data (plus optional intent/session digests), and the contract verifies the SecureConfirm proof + WebAuthn signature before any signing session is released.


## SecureConfirm Challenge Construction

SecureConfirm challenges bind fresh blockchain data to prevent replay attacks. The SecureConfirm worker builds the input from NEAR chain state:

| Field | Purpose | Source |
|-------|---------|--------|
| `domain_separator` | Prevents cross-protocol collisions | Fixed constant (`"web3_authn_challenge_v4"`) |
| `user_id` | Binds challenge to the NEAR account | Client (NEAR account ID) |
| `relying_party_id` | Binds to the wallet origin | Client config (wallet origin / rpId) |
| `block_height` | Enforces freshness window | NEAR RPC |
| `block_hash` | Protects across forks/reorgs | NEAR RPC |
| `intent_digest_32` (optional) | Binds a canonical intent payload to the challenge | SDK (base64url 32 bytes) |
| `session_policy_digest_32` (optional) | Binds relayer session policy to the challenge | SDK/relayer (base64url 32 bytes) |

The challenge input is `sha256(domain_separator || user_id || rp_id_lower || block_height_le || block_hash || intent_digest_32? || session_policy_digest_32?)`. `rp_id` is lowercased to match on-chain derivation and `block_height` is encoded as little-endian bytes.

**Intent digest binding:** when present, `intent_digest_32` is the canonical digest of the signing payload (tx/delegate/NEP-413) or threshold keygen intent. For threshold signing, the relayer recomputes this digest from the `signingPayload` and rejects any `signing_digest_32` that does not match the SecureConfirm‑bound intent.

**SecureConfirm security properties:**
- **Unpredictable** - SecureConfirm outputs indistinguishable from random
- **Verifiable** - Anyone can verify the challenge came from the user's public key
- **Non-malleable** - Requires private key to generate valid proofs
- **Fresh** - Blockheight and blockhash bound challenges expire rapidly, preventing replay attacks
- **Account-scoped** - SecureConfirm public keys are tied to NEAR accounts onchain

### Meeting WebAuthn Challenge Freshness Requirements

Traditional WebAuthn requires a server to mint and track challenges. SecureConfirm challenges meet these requirements via blockchain state and on-chain verification—no server storage needed:

**Challenge Uniqueness**
- Traditional: Server generates cryptographically random nonce for each request
- SecureConfirm: Combines `domain_separator` + `user_id` + `rp_id` + `block_height` + `block_hash` (+ optional digests); the SecureConfirm output is deterministic for that exact chain state and origin but indistinguishable from random.

**Time-Limited Validity**
- Traditional: Server sets timeout and rejects expired challenges
- SecureConfirm: the contract enforces a block-height freshness window on-chain. Older challenges are rejected.

**Stateless Verification**
- Traditional: Server validates signed challenge matches the stored one
- SecureConfirm: Contract recomputes the SecureConfirm input and verifies the proof; no storage required.

Relayer can make a single contract view `verify_authentication_response`; no DB of "issued challenges" is needed.

This is why SecureConfirm+contract verification works as a stateless replacement for WebAuthn challenge/response.

**Replay Attack Prevention**
- Traditional: Server marks used challenges to prevent reuse
- SecureConfirm: Combination of block height freshness and account/origin-bound inputs prevents replay. An attacker cannot reuse a signed challenge because:
  - The block height becomes stale (outside the contract’s freshness window)
  - The challenge is bound to a specific user account, origin, and blockchain state
  - The SecureConfirm proof cryptographically links the challenge to that exact input (user_id + rp_id + block data)

### Replay Attack Window and Mitigation

**The Time Window:** An attacker who intercepts a valid SecureConfirm proof + WebAuthn signature has a narrow window (up to 60 seconds). Within this window, they could try to replay the authentication (WebAuthn approval—not the NEAR transaction, which has nonce protection).

1. **NEAR Transaction Nonces** - NEAR blockchain has accounts nonces tied to the account's access key. Even if an attacker replays a valid WebAuthn authentication, they cannot replay the same transaction.

2. **Intent + signing digest binding (implemented)** The SecureConfirm input includes `intent_digest_32` derived from the canonical signing payload. For threshold signing, the relayer recomputes the intent digest and validates `signing_digest_32` (tx, delegate, or NEP‑413) before authorizing any co‑signature.

3. **Include NEAR nonce in SecureConfirm challenges** - Alternatively we could include the NEAR nonce in the SecureConfirm challenge and make it cryptographically binding, however this requires nonce synchronization and makes it harder to sign concurrent WebAuthn actions with little extra benefit.

### Summary
SecureConfirm challenges provide equivalent security to traditional WebAuthn challenge freshness, but verified on-chain without requiring server-side state or challenge storage.


## WebAuthn Contract Verification

During transaction signing, the SecureConfirm worker generates a challenge and the user approves with biometric authentication. The contract verifies both artifacts before the signer worker receives `WrapKeySeed`.

**1. Generate SecureConfirm challenge**

The WASM worker builds the SecureConfirm input from blockchain state and session data, then generates a verifiable challenge:

```ts
const challengeData = await secureconfirmWorker.generate_secureconfirm_challenge({
  userId,
  rpId,
  blockHeight,
  blockHash,
  intentDigest, // base64url 32-byte digest
  sessionPolicyDigest32, // optional
})
// Returns: { secureconfirmOutput, secureconfirmProof, secureconfirmInput, secureconfirmPublicKey, ... }
```

**2. WebAuthn authentication**

The SecureConfirm output is used as the WebAuthn challenge, binding the SecureConfirm proof to the biometric signature:

```ts
const credential = await navigator.credentials.get({
  publicKey: {
    challenge: challengeData.secureconfirmOutput,  // SecureConfirm output as challenge
    // ... other options
  }
})
```

**3. Submit to WebAuthn Contract for verification**

The SecureConfirm worker or relayer submits both the SecureConfirm proof and WebAuthn signature for on-chain verification:

```rust
// Contract method signature
    pub fn verify_authentication_response(
        &self,
        secureconfirm_data: SecureConfirmVerificationData,
        webauthn_authentication: WebAuthnAuthenticationCredential,
    ) -> VerifiedAuthenticationResponse
```

See the on-chain Web3Authn contract on NEAR Blocks for implementation details: https://testnet.nearblocks.io/address/w3a-v1.testnet?tab=contract

The SecureConfirm worker can gate session minting on the Web3Authn contract verification of both the SecureConfirm proof and WebAuthn signature before releasing session keys:

```rust
// Simplified verification flow
fn verify_authentication_response(secureconfirm_data, webauthn_authentication) {
    // 1. Verify SecureConfirm proof against stored public key
    let secureconfirm_output = secureconfirm_verify(user_secureconfirm_pubkey, secureconfirm_data.input, secureconfirm_data.proof)?;

    // 2. Check freshness (block height within the contract's configured window)
    assert!(is_fresh(secureconfirm_data.block_height));

    // 3. Verify WebAuthn P256 signature against stored passkey
    verify_webauthn_signature(
        passkey_pubkey,
        webauthn_authentication,
        secureconfirm_output  // Challenge must match SecureConfirm output
    )?;

    // 4. Return verified response
}
```

**The contract verifies:**

1. **SecureConfirm Proof** - Verifies the proof matches the user's SecureConfirm public key stored on-chain, confirming the challenge was generated by the correct private key
2. **Challenge Binding** - Ensures the WebAuthn challenge equals the SecureConfirm output, preventing challenge substitution attacks
3. **Freshness** - Validates block height is recent (within the contract’s freshness window), preventing replay attacks with old challenges
4. **Intent/Policy binding (when present)** - Recomputes the SecureConfirm input with `intent_digest_32` and/or `session_policy_digest_32` to ensure the proof is bound to the expected payload
5. **WebAuthn Signature** - Verifies the ECDSA P256 signature against the passkey's public key stored on-chain

**This gives us the following properties:**
- **Atomic verification** - Both SecureConfirm and WebAuthn must pass in a single transaction
- **Stateless** - No server state required; all verification happens on-chain
- **Cryptographically bound** - SecureConfirm output links blockchain state to biometric authentication
- **Replay protection** - Block-bound challenges prevent reuse


## Hybrid session unlock (SecureConfirm + WebAuthn + Shamir)

After verification succeeds, the wallet derives the unwrapping key entirely inside workers:

1. **PRF.first_auth** – Fresh TouchID/WebAuthn in the SecureConfirm worker yields `PRF.first_auth`.
2. **Primary: Shamir 3-pass** – SecureConfirm worker derives `shareA` from `PRF.first_auth`, runs the relay round trips, and reconstructs `secureconfirm_sk`. Backup Recovery Mode re-derives `secureconfirm_sk` from `PRF.second` only when explicitly requested.
3. **WrapKeySeed** – SecureConfirm worker derives `WrapKeySeed = HKDF(PRF.first_auth || secureconfirm_sk, "near-wrap-seed")`.
4. **KEK** – Signer worker receives only `WrapKeySeed + wrapKeySalt` over a dedicated `MessageChannel` and derives `KEK = HKDF(WrapKeySeed, wrapKeySalt)`.
5. **Decrypt + sign** – Signer worker decrypts `near_sk` with `KEK`, signs the NEAR transaction(s), and zeroizes secrets after the session.

**Isolation guarantees**
- PRF outputs and `secureconfirm_sk` never leave the SecureConfirm worker.
- Only `WrapKeySeed + wrapKeySalt` cross the worker boundary; main thread JS never sees `WrapKeySeed` or `near_sk`.
- PRF.second is reserved for registration/device linking/recovery and is zeroized immediately after use.


## Next steps

- Explore the [login flow](./architecture#login-flow) for smoother SecureConfirm unlocking UX
- Review [passkey scope strategies](passkey-scope)
