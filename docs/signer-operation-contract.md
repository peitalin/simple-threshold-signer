# Signer Operation Contract (v1)

Status: Active  
Last updated: 2026-02-14

## Scope

This document defines the canonical signer operation boundary shared by:

- `crates/signer-core`
- `crates/signer-platform-web`
- `crates/signer-platform-ios`
- worker/runtime callsites that invoke signer operations

## Versioning

- Contract version: `v1`
- Source of truth:
  - `crates/signer-core/src/operation.rs`
  - `crates/signer-core/src/error.rs`

`v1` operation families:

- `Codec`
- `Secp256k1`
- `NearEd25519`
- `NearCrypto`
- `Eip1559`
- `TempoTx`

## Request/Response Shape

### Multichain worker operations (EVM/Tempo)

```ts
type MultichainWorkerOperationRequest = {
  version?: number; // defaults to v1
  type: string;     // operation id
  payload: unknown; // deterministic JSON-compatible payload
  transfer?: Transferable[];
};
```

```ts
type MultichainWorkerOperationResult = unknown;
```

### Near signer operations

```ts
type NearWorkerOperationRequest = {
  version?: number; // defaults to v1
  sessionId?: string;
  type: number;     // WorkerRequestType
  payload: unknown;
  timeoutMs?: number;
  transfer?: Transferable[];
};
```

## Typed Error-Code Mapping

Canonical Rust error code enum:

- `SignerCoreErrorCode` in `crates/signer-core/src/error.rs`

Normative mapping for host surfaces:

| Rust code | Host code (normative) | Meaning |
|---|---|---|
| `InvalidInput` | `SIGNER_INVALID_INPUT` | Semantically invalid input value/shape. |
| `InvalidLength` | `SIGNER_INVALID_LENGTH` | Byte/string length mismatch. |
| `DecodeError` | `SIGNER_DECODE_ERROR` | Input decoding failed (hex/base64/base58/etc). |
| `EncodeError` | `SIGNER_ENCODE_ERROR` | Output encoding/serialization failed. |
| `HkdfError` | `SIGNER_KDF_ERROR` | HKDF/key-derivation failure. |
| `CryptoError` | `SIGNER_CRYPTO_ERROR` | Cryptographic verification or signing failure. |
| `Utf8Error` | `SIGNER_UTF8_ERROR` | UTF-8 conversion failure. |
| `Unsupported` | `SIGNER_UNSUPPORTED` | Unsupported operation/feature in current mode. |
| `Internal` | `SIGNER_INTERNAL` | Internal error (unexpected invariant break). |

Current compatibility note:

- Some worker-facing layers still propagate string errors for backward compatibility.
- New code should preserve the canonical mapping above when converting Rust errors into host errors/logs.

## Required Error Semantics (v1)

- Do not rely on ad-hoc string matching in new callsites.
- Keep stable message substrings for existing regression vectors until all callers migrate to typed host codes.
- Always preserve causal context in message text (field name + invariant).

## Canonical Invalid-Vector Coverage (v1)

The canonical vector corpus lives at:

- `crates/signer-core/fixtures/signing-vectors/v1.json`

Invalid regression coverage includes:

- EIP-1559 invalid signature length (`signature65 must be 65 bytes`)
- Tempo MVP unsupported auth fields
- NEP-413 invalid nonce length (`expected 32 bytes`)

Parity replay coverage:

- `crates/signer-platform-web/src/tests.rs`
- `crates/signer-platform-ios/src/tests.rs`
- `tests/unit/signingVectors.webWasmReplay.unit.test.ts`
