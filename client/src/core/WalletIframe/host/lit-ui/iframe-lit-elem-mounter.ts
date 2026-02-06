
/**
 * Lit Element Mounter - Host-Side Execution Layer
 *
 * This module manages Lit-based UI components inside the wallet iframe. It provides
 * a bridge between the parent application and UI components that need to run in
 * the wallet origin for proper WebAuthn activation.
 *
 * Key Responsibilities:
 * - Component Mounting: Creates and mounts Lit UI components on demand
 * - Event Wiring: Connects UI interactions to TatchiPasskey methods
 * - Lifecycle Management: Handles mount/unmount/update operations
 * - Message API: Exposes window.postMessage interface for parent communication
 * - Component Registry: Uses declarative registry for component definitions
 * - TatchiPasskey Integration: Wires UI actions to actual wallet operations
 *
 * Architecture:
 * - Maintains mounted component instances by ID
 * - Provides typed prop/event bindings for TatchiPasskey actions
 * - Handles both direct component mounting and registry-based mounting
 *
 * Message Protocol:
 * - WALLET_UI_MOUNT: Mount a component with specified props
 * - WALLET_UI_UPDATE: Update props of existing component
 * - WALLET_UI_UNMOUNT: Remove a mounted component
 * - WALLET_UI_REGISTER_TYPES: Register new component types
 */

// Import arrow register button so it's defined and not tree-shaken in wallet origin
import type { TatchiPasskeyIframe } from '../../TatchiPasskeyIframe';
import type { TatchiPasskey } from '../../../TatchiPasskey';
import type { SignAndSendTransactionHooksOptions } from '../../../types/sdkSentEvents';
import {
  fromTransactionInputsWasm,
  type ActionResult,
  type TatchiConfigsInput,
  type TransactionInput,
  type TransactionInputWasm
} from '../../../types';
import { uiBuiltinRegistry, type PmActionName, type WalletUIRegistry } from './iframe-lit-element-registry';
import { errorMessage } from '../../../../../../shared/src/utils/errors';
import { isObject, isString, toTrimmedString } from '../../../../../../shared/src/utils/validation';
import { type SignerMode, coerceSignerMode } from '../../../types/signer-worker';
import { ensureHostBaseStyles, markContainer, setContainerAnchored, clearContainerRule, HostMounterClasses } from './mounter-styles';

export type EnsureTatchiPasskey = () => void;
export type GetPasskeyManager = () => TatchiPasskey | TatchiPasskeyIframe | null; // Avoid tight coupling to class type
export type UpdateWalletConfigs = (patch: Partial<TatchiConfigsInput>) => void;

type StructuredPrimitive = string | number | boolean | null;
type StructuredValue =
  | StructuredPrimitive
  | undefined
  | bigint
  | Uint8Array
  | StructuredValue[]
  | { [key: string]: StructuredValue };

type UiProps = Record<string, StructuredValue>;
type UiActionArgs = Record<string, StructuredValue>;

type SignAndSendArgs = UiActionArgs & {
  nearAccountId?: string;
  transactions?: TransactionInput[] | TransactionInputWasm[];
  txSigningRequests?: TransactionInput[] | TransactionInputWasm[];
  options?: SignAndSendTransactionHooksOptions;
};

type PmActionArgsMap = {
  signAndSendTransactions: SignAndSendArgs;
};

type PmActionResultMap = {
  signAndSendTransactions: ActionResult[];
};

type PmActionArgs = PmActionArgsMap[PmActionName];
type PmActionResult = PmActionResultMap[PmActionName];

type WalletUiMountPayload = { key: string; props?: UiProps; targetSelector?: string; id?: string };
type WalletUiUpdatePayload = { id: string; props?: UiProps };
type WalletUiUnmountPayload = { id: string };

type WalletUiInboundPayloadMap = {
  WALLET_SET_CONFIG: Partial<TatchiConfigsInput>;
  WALLET_UI_REGISTER_TYPES: WalletUIRegistry;
  WALLET_UI_MOUNT: WalletUiMountPayload;
  WALLET_UI_UPDATE: WalletUiUpdatePayload;
  WALLET_UI_UNMOUNT: WalletUiUnmountPayload;
};

type WalletUiInboundType = keyof WalletUiInboundPayloadMap;

type WalletUiInboundMessage = {
  [K in WalletUiInboundType]: { type: K; payload?: WalletUiInboundPayloadMap[K] }
}[WalletUiInboundType];

type WalletUiActionResultPayload = {
  ok: boolean;
  id: string;
  result?: StructuredValue | PmActionResult;
  error?: string;
  cancelled?: boolean;
};

type WalletUiOutboundMessage =
  | { type: 'WALLET_UI_EVENT'; payload: { id: string; key: string; event: string } }
  | { type: 'WALLET_UI_ANCHOR_ENTER' | 'WALLET_UI_ANCHOR_LEAVE'; payload: { id: string } }
  | { type: string; payload: WalletUiActionResultPayload };

type UiActionHandler = (args: UiActionArgs) => Promise<PmActionResult>;
type UiResultHandler = (result: StructuredValue | PmActionResult) => void;
type UiCancelHandler = () => void;
type UiElementProp = StructuredValue | UiActionHandler | UiResultHandler | UiCancelHandler;
type UiElement = HTMLElement & Record<string, UiElementProp>;
type UiComponentDef = WalletUIRegistry[string];
type UiEventBinding = NonNullable<UiComponentDef['eventBindings']>[number];

type ViewportRect = { top: number; left: number; width: number; height: number };
type MountedEntry = {
  id: string;
  element: UiElement;
  container?: HTMLElement;
  anchorMode?: 'iframe' | 'viewport';
  root: HTMLElement;
  targetSelector?: string;
  allowedProps?: Set<string>;
};

type SetupLitElemMounterOptions = {
  ensureTatchiPasskey: EnsureTatchiPasskey;
  getTatchiPasskey: GetPasskeyManager;
  updateWalletConfigs: UpdateWalletConfigs;
  postToParent: (message: WalletUiOutboundMessage) => void;
};

type PostToParent = (message: WalletUiOutboundMessage) => void;
type RunPmAction = <T extends PmActionName>(
  action: T,
  args: PmActionArgsMap[T]
) => Promise<PmActionResultMap[T]>;

const isWasmTransactionInput = (tx: TransactionInput | TransactionInputWasm): tx is TransactionInputWasm => {
  return Array.isArray(tx.actions) && tx.actions.some((action: unknown) => isObject(action) && 'action_type' in action);
};

const normalizeTransactions = (candidate?: TransactionInput[] | TransactionInputWasm[]): TransactionInput[] => {
  if (!Array.isArray(candidate) || candidate.length === 0) return [];
  if (candidate.every(isWasmTransactionInput)) {
    return fromTransactionInputsWasm(candidate as TransactionInputWasm[]);
  }
  return candidate as TransactionInput[];
};

const coerceViewportRect = (value: StructuredValue): ViewportRect | null => {
  if (!isObject(value)) return null;
  const rect = value as Partial<Record<keyof ViewportRect, StructuredValue>>;
  const top = Number(rect.top);
  const left = Number(rect.left);
  const width = Number(rect.width);
  const height = Number(rect.height);
  if (![top, left, width, height].every((n) => Number.isFinite(n))) return null;
  return { top, left, width, height };
};

const pickRoot = (selector?: string | null): HTMLElement => {
  try {
    if (selector && isString(selector)) {
      const el = document.querySelector(selector);
      if (el && el instanceof HTMLElement) return el;
    }
  } catch {}
  return document.body || document.documentElement;
};

const applyProps = (el: UiElement, props: UiProps, allowedProps?: Set<string>) => {
  if (!props) return;
  for (const [k, v] of Object.entries(props)) {
    if (allowedProps && !allowedProps.has(k)) continue;
    try { (el as Record<string, UiElementProp>)[k] = v; } catch {}
  }
};

const resolveProps = (def: UiComponentDef, payload?: WalletUiMountPayload): UiProps => {
  return { ...(def.propDefaults || {}), ...(payload?.props || {}) } as UiProps;
};

const resolveTargetSelector = (payload: WalletUiMountPayload | undefined, props: UiProps): string | undefined => {
  return isString(props.targetSelector) ? props.targetSelector : payload?.targetSelector;
};

const resolveAnchorMode = (props: UiProps): 'iframe' | 'viewport' => {
  return props.anchorMode === 'iframe' ? 'iframe' : 'viewport';
};

const buildArgsFromProps = (el: UiElement, binding: UiEventBinding): PmActionArgs => {
  const args: PmActionArgs = {};
  if (!binding.argsFromProps) return args;
  for (const [argName, propKey] of Object.entries(binding.argsFromProps)) {
    const propValue = el[propKey];
    if (typeof propValue !== 'function') {
      args[argName] = propValue;
    }
  }
  return args;
};

const resolveComponentDef = (uiRegistry: WalletUIRegistry, key?: string): UiComponentDef | null => {
  if (!key) {
    console.warn('[ElemMounter:UI] Unknown component key:', key);
    return null;
  }
  const def = uiRegistry[key];
  if (!def || !def.tag) {
    console.warn('[ElemMounter:UI] Unknown component key:', key);
    return null;
  }
  return def;
};

const postActionError = (postToParent: PostToParent, binding: UiEventBinding, id: string, err: unknown) => {
  const type = binding.resultMessageType || 'UI_ACTION_RESULT';
  postToParent({ type, payload: { ok: false, id, error: errorMessage(err) } });
};

const wireEventBindings = (
  el: UiElement,
  def: UiComponentDef,
  componentKey: string,
  id: string,
  postToParent: PostToParent,
  runPmAction: RunPmAction
) => {
  if (!Array.isArray(def.eventBindings)) return;
  for (const binding of def.eventBindings) {
    el.addEventListener(binding.event, async () => {
      try {
        postToParent({ type: 'WALLET_UI_EVENT', payload: { id, key: componentKey, event: binding.event } });
        const args = buildArgsFromProps(el, binding) as PmActionArgsMap[typeof binding.action];
        const result = await runPmAction(binding.action, args);
        if (binding.resultMessageType) {
          postToParent({ type: binding.resultMessageType, payload: { ok: true, id, result } });
        }
      } catch (err) {
        postActionError(postToParent, binding, id, err);
      }
    });
  }
};

const wirePropBindings = (el: UiElement, def: UiComponentDef, runPmAction: RunPmAction) => {
  if (!Array.isArray(def.propBindings)) return;
  for (const binding of def.propBindings) {
    const action = binding.action;
    el[binding.prop] = (args: UiActionArgs) => runPmAction(action, args as PmActionArgsMap[typeof action]);
  }
};

const wireBridgeProps = (el: UiElement, def: UiComponentDef, id: string, postToParent: PostToParent) => {
  const bridge = def.bridgeProps;
  if (!bridge) return;
  if (bridge.successProp) {
    el[bridge.successProp] = (result: StructuredValue | PmActionResult) => {
      postToParent({ type: bridge.messageType, payload: { ok: true, id, result } });
    };
  }
  if (bridge.cancelProp) {
    el[bridge.cancelProp] = () => {
      postToParent({ type: bridge.messageType, payload: { ok: false, id, cancelled: true } });
    };
  }
};

const mountAnchored = (
  el: UiElement,
  id: string,
  rect: ViewportRect,
  anchorMode: 'iframe' | 'viewport',
  root: HTMLElement,
  postToParent: PostToParent
): HTMLElement => {
  const container = document.createElement('div');
  markContainer(container);
  setContainerAnchored(container, rect, anchorMode);
  container.appendChild(el);
  container.addEventListener('pointerenter', () => {
    postToParent({ type: 'WALLET_UI_ANCHOR_ENTER', payload: { id } });
  });
  container.addEventListener('pointerleave', () => {
    postToParent({ type: 'WALLET_UI_ANCHOR_LEAVE', payload: { id } });
  });
  root.appendChild(container);
  return container;
};

export function setupLitElemMounter(opts: SetupLitElemMounterOptions) {
  const { ensureTatchiPasskey, getTatchiPasskey, updateWalletConfigs } = opts;

  // Generic registry for mountable components
  let uiRegistry: WalletUIRegistry = { ...uiBuiltinRegistry };
  let uidCounter = 0;
  const mountedById = new Map<string, MountedEntry>();
  let parentOrigin: string | null = null;

  // Ensure global host styles via stylesheet (no inline style attributes)
  ensureHostBaseStyles();

  const runPmAction = async <T extends PmActionName>(
    action: T,
    args: PmActionArgsMap[T]
  ): Promise<PmActionResultMap[T]> => {
    ensureTatchiPasskey();
    const pm = getTatchiPasskey();
    if (!pm) {
      throw new Error('Passkey manager not initialized');
    }
    switch (action) {
      case 'signAndSendTransactions': {
        const input = args as SignAndSendArgs;
        const nearAccountId = toTrimmedString(input.nearAccountId);
        const transactions = normalizeTransactions(input.transactions || input.txSigningRequests);
        const options = (input.options || {}) as SignAndSendTransactionHooksOptions;
        const signerModeInput = (options as { signerMode?: SignerMode | SignerMode['mode'] | null }).signerMode;
        const signerMode = coerceSignerMode(signerModeInput, pm?.configs?.signerMode);
        if (!nearAccountId || transactions.length === 0) {
          throw new Error('nearAccountId and transactions required');
        }
        return await pm.signAndSendTransactions({
          nearAccountId,
          transactions,
          options: { ...options, signerMode }
        });
      }
      default:
        throw new Error(`Unknown pm action: ${action}`);
    }
  };

  const mountUiComponent = (payload?: WalletUiMountPayload) => {
    const componentKey = payload?.key;
    const def = resolveComponentDef(uiRegistry, componentKey);
    if (!def || !componentKey) return null;
    const id = payload?.id ?? `w3a-ui-${++uidCounter}`;
    const rawProps: UiProps = payload?.props || {};
    const props = resolveProps(def, payload);
    const allowedProps = def.allowedProps ? new Set(def.allowedProps) : undefined;
    if (allowedProps) {
      allowedProps.add('viewportRect');
      allowedProps.add('anchorMode');
      allowedProps.add('targetSelector');
    }
    // If already mounted with same id, perform an update instead of mounting a duplicate
    if (mountedById.has(id)) {
      updateUiComponent({ id, props: rawProps });
      return id;
    }
    const el = document.createElement(def.tag) as UiElement;
    el.classList.add(HostMounterClasses.ELEMENT);
    applyProps(el, props, allowedProps);

    wireEventBindings(el, def, componentKey, id, opts.postToParent, runPmAction);
    wirePropBindings(el, def, runPmAction);
    wireBridgeProps(el, def, id, opts.postToParent);

    // Optional: viewportRect anchoring → wrap element in fixed-position container
    const rect = coerceViewportRect(rawProps.viewportRect);
    const anchorMode = resolveAnchorMode(rawProps);
    const targetSelector = resolveTargetSelector(payload, rawProps);
    const root = pickRoot(targetSelector);
    if (rect) {
      const container = mountAnchored(el, id, rect, anchorMode, root, opts.postToParent);
      mountedById.set(id, { id, element: el, container, anchorMode, root, targetSelector, allowedProps });
    } else {
      root.appendChild(el);
      mountedById.set(id, { id, element: el, root, targetSelector, allowedProps });
    }
    return id;
  };

  const updateUiComponent = (payload: WalletUiUpdatePayload) => {
    const entry = mountedById.get(payload.id);
    if (!entry) return false;
    const props: UiProps = payload?.props || {};
    const rect = coerceViewportRect(props.viewportRect);
    const anchorMode = resolveAnchorMode(props);
    const hasTargetSelector = Object.prototype.hasOwnProperty.call(props, 'targetSelector');
    const nextTargetSelector = hasTargetSelector && isString(props.targetSelector)
      ? props.targetSelector
      : undefined;
    const nextRoot = hasTargetSelector ? pickRoot(nextTargetSelector) : entry.root;
    const wantsUnanchor = Object.prototype.hasOwnProperty.call(props, 'viewportRect') && props.viewportRect === null;

    // If entry is anchored, update container + child props
    if (entry.container) {
      if (nextRoot !== entry.root) {
        nextRoot.appendChild(entry.container);
        entry.root = nextRoot;
        entry.targetSelector = nextTargetSelector;
      }
      if (rect) {
        setContainerAnchored(entry.container, rect, anchorMode);
        entry.anchorMode = anchorMode;
      } else if (wantsUnanchor) {
        clearContainerRule(entry.container);
        entry.container.remove();
        entry.container = undefined;
        entry.anchorMode = undefined;
        entry.root = nextRoot;
        entry.targetSelector = nextTargetSelector;
        nextRoot.appendChild(entry.element);
      }
      applyProps(entry.element, props, entry.allowedProps);
      return true;
    }

    // Otherwise node is the custom element itself
    if (nextRoot !== entry.root) {
      nextRoot.appendChild(entry.element);
      entry.root = nextRoot;
      entry.targetSelector = nextTargetSelector;
    }
    if (rect) {
      const container = mountAnchored(entry.element, payload.id, rect, anchorMode, nextRoot, opts.postToParent);
      entry.container = container;
      entry.anchorMode = anchorMode;
    }
    applyProps(entry.element, props, entry.allowedProps);
    return true;
  };

  const unmountUiComponent = (payload: WalletUiUnmountPayload) => {
    const entry = mountedById.get(payload.id);
    if (!entry) return false;
    if (entry.container) {
      clearContainerRule(entry.container);
      entry.container.remove();
    } else {
      entry.element.remove();
    }
    mountedById.delete(payload.id);
    return true;
  };

  const messageHandlers: { [K in WalletUiInboundType]: (payload: WalletUiInboundPayloadMap[K] | undefined) => void } = {
    WALLET_SET_CONFIG: (payload) => {
      updateWalletConfigs(payload || {});
      // uiRegistry is no longer read from configs; register via WALLET_UI_REGISTER_TYPES or PM_SET_CONFIG
    },
    WALLET_UI_REGISTER_TYPES: (payload) => {
      if (payload && isObject(payload)) {
        uiRegistry = { ...uiRegistry, ...payload };
      }
    },
    WALLET_UI_MOUNT: (payload) => {
      mountUiComponent(payload);
    },
    WALLET_UI_UPDATE: (payload) => {
      if (payload) updateUiComponent(payload);
    },
    WALLET_UI_UNMOUNT: (payload) => {
      if (payload) unmountUiComponent(payload);
    },
  };

  const isTrustedMessage = (evt: MessageEvent): boolean => {
    if (evt.source === window) return true;
    if (evt.source !== window.parent) return false;
    const origin = evt.origin;
    if (parentOrigin && origin && origin !== 'null' && origin !== parentOrigin) return false;
    if (!parentOrigin && origin && origin !== 'null') parentOrigin = origin;
    return true;
  };

  window.addEventListener('message', (evt: MessageEvent<WalletUiInboundMessage>) => {
    if (!isTrustedMessage(evt)) return;
    const data = evt?.data;
    if (!data || !isObject(data) || !('type' in data)) return;
    const message = data as WalletUiInboundMessage;
    const handler = messageHandlers[message.type] as
      | ((payload: WalletUiInboundPayloadMap[typeof message.type] | undefined) => void)
      | undefined;
    if (handler) handler(message.payload);
  });
}
