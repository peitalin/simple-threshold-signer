import __buffer_polyfill from 'vite-plugin-node-polyfills/shims/buffer'
globalThis.Buffer = globalThis.Buffer || __buffer_polyfill
import __global_polyfill from 'vite-plugin-node-polyfills/shims/global'
globalThis.global = globalThis.global || __global_polyfill
import __process_polyfill from 'vite-plugin-node-polyfills/shims/process'
globalThis.process = globalThis.process || __process_polyfill

import {
  encodeToCurve,
  hashToCurve,
  schnorr,
  secp256k1,
  secp256k1_hasher
} from "./chunk-IGDTNDNM.js";
import "./chunk-ANUX2B4O.js";
import "./chunk-P56LWUW6.js";
export {
  encodeToCurve,
  hashToCurve,
  schnorr,
  secp256k1,
  secp256k1_hasher
};
//# sourceMappingURL=secp256k1-BP63LPDC.js.map
