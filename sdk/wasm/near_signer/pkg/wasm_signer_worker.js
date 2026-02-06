// Dev/runtime shim for monorepo usage.
//
// The server-side SDK code in `sdk/dist/esm/server/**` imports the wasm-pack
// JS glue via a relative path that resolves to `sdk/wasm/...` at runtime.
// In this monorepo, the actual wasm-pack output lives at the repo root under
// `wasm/near_signer/pkg`, so we re-export it from here.
export * from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
export { default } from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';

