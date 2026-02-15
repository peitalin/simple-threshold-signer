## Summary

- <!-- What changed? -->

## Validation

- [ ] `pnpm -s check:signing-architecture`
- [ ] `pnpm -s check:signer-parity` (if touching signer Rust/platform crates)
- [ ] Additional targeted tests (list below)

## Signing Crypto Boundary Checklist (if touching signing code)

- [ ] No new signing-critical crypto math added in `client/src/core/signing/**`
- [ ] Runtime signing paths do not import `@noble/*`
- [ ] New signing-critical logic is implemented in Rust/wasm worker path
- [ ] No reintroduction of removed TS helpers (`eip1559.ts`, `keccak.ts`, `rlp.ts`, `tempoTx.ts`, secp256k1 local derivation helpers)
- [ ] Worker operation additions are reflected in typed contracts (`backends/types.ts`) and wrappers

## Docs

- [ ] Updated `docs/crypto-in-wasm.md` and/or `docs/rust-ios-core.md` when scope/phase status changed
