import __buffer_polyfill from 'vite-plugin-node-polyfills/shims/buffer'
globalThis.Buffer = globalThis.Buffer || __buffer_polyfill
import __global_polyfill from 'vite-plugin-node-polyfills/shims/global'
globalThis.global = globalThis.global || __global_polyfill
import __process_polyfill from 'vite-plugin-node-polyfills/shims/process'
globalThis.process = globalThis.process || __process_polyfill

import {
  require_crypto_browserify
} from "./chunk-62YMZ2P2.js";
import "./chunk-4WHPUJTV.js";
import "./chunk-3G433QNW.js";
import "./chunk-YKRHS4FH.js";
import "./chunk-LMHGXO7T.js";
import "./chunk-P56LWUW6.js";
export default require_crypto_browserify();
//# sourceMappingURL=crypto-browserify.js.map
