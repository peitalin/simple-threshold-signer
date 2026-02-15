import __buffer_polyfill from 'vite-plugin-node-polyfills/shims/buffer'
globalThis.Buffer = globalThis.Buffer || __buffer_polyfill
import __global_polyfill from 'vite-plugin-node-polyfills/shims/global'
globalThis.global = globalThis.global || __global_polyfill
import __process_polyfill from 'vite-plugin-node-polyfills/shims/process'
globalThis.process = globalThis.process || __process_polyfill

import {
  _$LH
} from "./chunk-BIWRFNGK.js";
import {
  __toESM,
  init_define_process_env,
  require_dist,
  require_dist2,
  require_dist3
} from "./chunk-P56LWUW6.js";

// ../../node_modules/lit-html/development/directive-helpers.js
init_define_process_env();
var import_dist = __toESM(require_dist(), 1);
var import_dist2 = __toESM(require_dist2(), 1);
var import_dist3 = __toESM(require_dist3(), 1);
var { _ChildPart: ChildPart } = _$LH;
var ENABLE_SHADYDOM_NOPATCH = true;
var _a, _b;
var wrap = ENABLE_SHADYDOM_NOPATCH && ((_a = window.ShadyDOM) == null ? void 0 : _a.inUse) && ((_b = window.ShadyDOM) == null ? void 0 : _b.noPatch) === true ? window.ShadyDOM.wrap : (node) => node;
var isSingleExpression = (part) => part.strings === void 0;
var createMarker = () => document.createComment("");
var insertPart = (containerPart, refPart, part) => {
  var _a2;
  const container = wrap(containerPart._$startNode).parentNode;
  const refNode = refPart === void 0 ? containerPart._$endNode : refPart._$startNode;
  if (part === void 0) {
    const startNode = wrap(container).insertBefore(createMarker(), refNode);
    const endNode = wrap(container).insertBefore(createMarker(), refNode);
    part = new ChildPart(startNode, endNode, containerPart, containerPart.options);
  } else {
    const endNode = wrap(part._$endNode).nextSibling;
    const oldParent = part._$parent;
    const parentChanged = oldParent !== containerPart;
    if (parentChanged) {
      (_a2 = part._$reparentDisconnectables) == null ? void 0 : _a2.call(part, containerPart);
      part._$parent = containerPart;
      let newConnectionState;
      if (part._$notifyConnectionChanged !== void 0 && (newConnectionState = containerPart._$isConnected) !== oldParent._$isConnected) {
        part._$notifyConnectionChanged(newConnectionState);
      }
    }
    if (endNode !== refNode || parentChanged) {
      let start = part._$startNode;
      while (start !== endNode) {
        const n = wrap(start).nextSibling;
        wrap(container).insertBefore(start, refNode);
        start = n;
      }
    }
  }
  return part;
};
var setChildPartValue = (part, value, directiveParent = part) => {
  part._$setValue(value, directiveParent);
  return part;
};
var RESET_VALUE = {};
var setCommittedValue = (part, value = RESET_VALUE) => part._$committedValue = value;
var getCommittedValue = (part) => part._$committedValue;
var removePart = (part) => {
  part._$clear();
  part._$startNode.remove();
};

// ../../node_modules/lit-html/development/directive.js
init_define_process_env();
var import_dist4 = __toESM(require_dist(), 1);
var import_dist5 = __toESM(require_dist2(), 1);
var import_dist6 = __toESM(require_dist3(), 1);
var PartType = {
  ATTRIBUTE: 1,
  CHILD: 2,
  PROPERTY: 3,
  BOOLEAN_ATTRIBUTE: 4,
  EVENT: 5,
  ELEMENT: 6
};
var directive = (c) => (...values) => ({
  // This property needs to remain unminified.
  ["_$litDirective$"]: c,
  values
});
var Directive = class {
  constructor(_partInfo) {
  }
  // See comment in Disconnectable interface for why this is a getter
  get _$isConnected() {
    return this._$parent._$isConnected;
  }
  /** @internal */
  _$initialize(part, parent, attributeIndex) {
    this.__part = part;
    this._$parent = parent;
    this.__attributeIndex = attributeIndex;
  }
  /** @internal */
  _$resolve(part, props) {
    return this.update(part, props);
  }
  update(_part, props) {
    return this.render(...props);
  }
};

export {
  isSingleExpression,
  insertPart,
  setChildPartValue,
  setCommittedValue,
  getCommittedValue,
  removePart,
  PartType,
  directive,
  Directive
};
/*! Bundled license information:

lit-html/development/directive-helpers.js:
  (**
   * @license
   * Copyright 2020 Google LLC
   * SPDX-License-Identifier: BSD-3-Clause
   *)

lit-html/development/directive.js:
  (**
   * @license
   * Copyright 2017 Google LLC
   * SPDX-License-Identifier: BSD-3-Clause
   *)
*/
//# sourceMappingURL=chunk-THIL6POA.js.map
