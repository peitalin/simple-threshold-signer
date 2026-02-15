import __buffer_polyfill from 'vite-plugin-node-polyfills/shims/buffer'
globalThis.Buffer = globalThis.Buffer || __buffer_polyfill
import __global_polyfill from 'vite-plugin-node-polyfills/shims/global'
globalThis.global = globalThis.global || __global_polyfill
import __process_polyfill from 'vite-plugin-node-polyfills/shims/process'
globalThis.process = globalThis.process || __process_polyfill

import {
  Directive,
  PartType,
  directive,
  getCommittedValue,
  insertPart,
  removePart,
  setChildPartValue,
  setCommittedValue
} from "./chunk-THIL6POA.js";
import {
  noChange
} from "./chunk-BIWRFNGK.js";
import {
  __toESM,
  init_define_process_env,
  require_dist,
  require_dist2,
  require_dist3
} from "./chunk-P56LWUW6.js";

// ../../node_modules/lit/directives/repeat.js
init_define_process_env();
var import_dist4 = __toESM(require_dist());
var import_dist5 = __toESM(require_dist2());
var import_dist6 = __toESM(require_dist3());

// ../../node_modules/lit-html/development/directives/repeat.js
init_define_process_env();
var import_dist = __toESM(require_dist());
var import_dist2 = __toESM(require_dist2());
var import_dist3 = __toESM(require_dist3());
var generateMap = (list, start, end) => {
  const map = /* @__PURE__ */ new Map();
  for (let i = start; i <= end; i++) {
    map.set(list[i], i);
  }
  return map;
};
var RepeatDirective = class extends Directive {
  constructor(partInfo) {
    super(partInfo);
    if (partInfo.type !== PartType.CHILD) {
      throw new Error("repeat() can only be used in text expressions");
    }
  }
  _getValuesAndKeys(items, keyFnOrTemplate, template) {
    let keyFn;
    if (template === void 0) {
      template = keyFnOrTemplate;
    } else if (keyFnOrTemplate !== void 0) {
      keyFn = keyFnOrTemplate;
    }
    const keys = [];
    const values = [];
    let index = 0;
    for (const item of items) {
      keys[index] = keyFn ? keyFn(item, index) : index;
      values[index] = template(item, index);
      index++;
    }
    return {
      values,
      keys
    };
  }
  render(items, keyFnOrTemplate, template) {
    return this._getValuesAndKeys(items, keyFnOrTemplate, template).values;
  }
  update(containerPart, [items, keyFnOrTemplate, template]) {
    const oldParts = getCommittedValue(containerPart);
    const { values: newValues, keys: newKeys } = this._getValuesAndKeys(items, keyFnOrTemplate, template);
    if (!Array.isArray(oldParts)) {
      this._itemKeys = newKeys;
      return newValues;
    }
    const oldKeys = this._itemKeys ?? (this._itemKeys = []);
    const newParts = [];
    let newKeyToIndexMap;
    let oldKeyToIndexMap;
    let oldHead = 0;
    let oldTail = oldParts.length - 1;
    let newHead = 0;
    let newTail = newValues.length - 1;
    while (oldHead <= oldTail && newHead <= newTail) {
      if (oldParts[oldHead] === null) {
        oldHead++;
      } else if (oldParts[oldTail] === null) {
        oldTail--;
      } else if (oldKeys[oldHead] === newKeys[newHead]) {
        newParts[newHead] = setChildPartValue(oldParts[oldHead], newValues[newHead]);
        oldHead++;
        newHead++;
      } else if (oldKeys[oldTail] === newKeys[newTail]) {
        newParts[newTail] = setChildPartValue(oldParts[oldTail], newValues[newTail]);
        oldTail--;
        newTail--;
      } else if (oldKeys[oldHead] === newKeys[newTail]) {
        newParts[newTail] = setChildPartValue(oldParts[oldHead], newValues[newTail]);
        insertPart(containerPart, newParts[newTail + 1], oldParts[oldHead]);
        oldHead++;
        newTail--;
      } else if (oldKeys[oldTail] === newKeys[newHead]) {
        newParts[newHead] = setChildPartValue(oldParts[oldTail], newValues[newHead]);
        insertPart(containerPart, oldParts[oldHead], oldParts[oldTail]);
        oldTail--;
        newHead++;
      } else {
        if (newKeyToIndexMap === void 0) {
          newKeyToIndexMap = generateMap(newKeys, newHead, newTail);
          oldKeyToIndexMap = generateMap(oldKeys, oldHead, oldTail);
        }
        if (!newKeyToIndexMap.has(oldKeys[oldHead])) {
          removePart(oldParts[oldHead]);
          oldHead++;
        } else if (!newKeyToIndexMap.has(oldKeys[oldTail])) {
          removePart(oldParts[oldTail]);
          oldTail--;
        } else {
          const oldIndex = oldKeyToIndexMap.get(newKeys[newHead]);
          const oldPart = oldIndex !== void 0 ? oldParts[oldIndex] : null;
          if (oldPart === null) {
            const newPart = insertPart(containerPart, oldParts[oldHead]);
            setChildPartValue(newPart, newValues[newHead]);
            newParts[newHead] = newPart;
          } else {
            newParts[newHead] = setChildPartValue(oldPart, newValues[newHead]);
            insertPart(containerPart, oldParts[oldHead], oldPart);
            oldParts[oldIndex] = null;
          }
          newHead++;
        }
      }
    }
    while (newHead <= newTail) {
      const newPart = insertPart(containerPart, newParts[newTail + 1]);
      setChildPartValue(newPart, newValues[newHead]);
      newParts[newHead++] = newPart;
    }
    while (oldHead <= oldTail) {
      const oldPart = oldParts[oldHead++];
      if (oldPart !== null) {
        removePart(oldPart);
      }
    }
    this._itemKeys = newKeys;
    setCommittedValue(containerPart, newParts);
    return noChange;
  }
};
var repeat = directive(RepeatDirective);
export {
  repeat
};
/*! Bundled license information:

lit-html/development/directives/repeat.js:
  (**
   * @license
   * Copyright 2017 Google LLC
   * SPDX-License-Identifier: BSD-3-Clause
   *)
*/
//# sourceMappingURL=lit_directives_repeat__js.js.map
