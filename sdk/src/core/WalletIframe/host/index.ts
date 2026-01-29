/**
 * Host entry helpers for the wallet iframe.
 *
 * Boot sequence (high-level):
 * 1) `initWalletIFrame()` runs early bootstrap defaults for the iframe document.
 * 2) A host context is created for wallet config + MessagePort state.
 * 3) The Lit UI mounter is registered for WALLET_UI_* messages.
 * 4) PM_* handlers are wired and CONNECT/READY listeners are attached.
 */
import { bootstrapTransparentHost } from './bootstrap';

import type {
  ParentToChildEnvelope,
  ParentToChildType,
  ChildToParentEnvelope,
  ReadyPayload,
  PMSetConfigPayload,
  PreferencesChangedPayload,
  ProgressPayload,
} from '../shared/messages';
import { CONFIRM_UI_ELEMENT_SELECTORS } from '../../WebAuthnManager/LitComponents/tags';
import { setupLitElemMounter } from './lit-ui/iframe-lit-elem-mounter';
import type { TatchiConfigsInput } from '../../types/tatchi';
import { isObject } from '@/utils/validation';
import { errorMessage } from '../../../utils/errors';
import { TatchiPasskey } from '../../TatchiPasskey';
import { WalletIframeDomEvents } from '../events';
// handlers moved to dedicated module; host no longer imports per-call hook types
import { createWalletIframeHandlers } from './wallet-iframe-handlers';
import { applyWalletConfig, createHostContext, ensurePasskeyManager } from './context';
import { addHostListeners, post as postMessage, postToParent as postToParentMessage } from './messaging';

const PROTOCOL: ReadyPayload['protocolVersion'] = '1.0.0';
let initialized = false;

export function initWalletIFrame(): void {
  if (initialized) return;
  initialized = true;

  // Early bootstrap (transparent surface, env shims, default asset base, telemetry)
  bootstrapTransparentHost();

  const ctx = createHostContext();

  // Track request-level cancellations
  const cancelledRequests = new Set<string>();
  const markCancelled = (rid?: string) => { if (rid) cancelledRequests.add(rid); };
  const isCancelled = (rid?: string) => !!rid && cancelledRequests.has(rid);
  const clearCancelled = (rid?: string) => { if (rid) cancelledRequests.delete(rid); };

  const post = (msg: ChildToParentEnvelope): void => {
    postMessage(ctx, msg);
  };

  const postToParent = (message: unknown): void => {
    postToParentMessage(ctx, message);
  };

  const postProgress = (requestId: string | undefined, payload: ProgressPayload): void => {
    if (!requestId) return;
    post({ type: 'PROGRESS', requestId, payload });
  };

  const emitCancellationPayload = (requestId: string | undefined): void => {
    if (!requestId) return;
    postProgress(requestId, { step: 0, phase: 'cancelled', status: 'error', message: 'Cancelled by user' });
    post({ type: 'ERROR', requestId, payload: { code: 'CANCELLED', message: 'Request cancelled' } });
  };

  const respondIfCancelled = (requestId: string | undefined): boolean => {
    if (!requestId || !isCancelled(requestId)) return false;
    emitCancellationPayload(requestId);
    clearCancelled(requestId);
    return true;
  };

  const ensureTatchiPasskey = (): TatchiPasskey => {
    const prev = ctx.tatchiPasskey;
    const pm = ensurePasskeyManager(ctx) as TatchiPasskey;
    if (prev !== pm) {
      const up = pm.userPreferences;

      // Bridge wallet-host preferences to the parent app so app UI can mirror wallet host state.
      ctx.prefsUnsubscribe?.();
      const emitPreferencesChanged = () => {
        const id = String(up.getCurrentUserAccountId?.() || '').trim();
        const nearAccountId = id ? id : null;
        post({
          type: 'PREFERENCES_CHANGED',
          payload: {
            nearAccountId,
            confirmationConfig: up.getConfirmationConfig(),
            signerMode: up.getSignerMode(),
            updatedAt: Date.now(),
          } satisfies PreferencesChangedPayload,
        });
      };
      const unsubCfg = up.onConfirmationConfigChange?.(() => emitPreferencesChanged()) || null;
      const unsubSignerMode = up.onSignerModeChange?.(() => emitPreferencesChanged()) || null;
      const unsubCurrentUser = up.onCurrentUserChange?.(() => emitPreferencesChanged()) || null;
      ctx.prefsUnsubscribe = () => {
        try { unsubCfg?.(); } catch {}
        try { unsubSignerMode?.(); } catch {}
        try { unsubCurrentUser?.(); } catch {}
      };
      // Emit a best-effort snapshot as soon as the host is ready.
      Promise.resolve().then(() => emitPreferencesChanged()).catch(() => {});
    }
    return pm;
  };

  const getTatchiPasskey = (): TatchiPasskey => ensureTatchiPasskey();

  // Unified handler map wired with minimal deps from this host
  const handlers = createWalletIframeHandlers({
    getTatchiPasskey: getTatchiPasskey,
    post,
    postProgress,
    postToParent,
    respondIfCancelled,
  });

  // Lightweight cross-origin control channel for small embedded UI surfaces (e.g., tx button).
  // This channel uses window.postMessage directly (not MessagePort) so that a standalone
  // iframe can instruct this host to render a clickable control that performs WebAuthn
  // operations within the same browsing context (satisfying user activation requirements).
  setupLitElemMounter({
    ensureTatchiPasskey: ensureTatchiPasskey,
    getTatchiPasskey: () => ctx.tatchiPasskey,
    updateWalletConfigs: (patch) => {
      ctx.walletConfigs = {
        ...(ctx.walletConfigs || ({} as TatchiConfigsInput)),
        ...patch,
      } as TatchiConfigsInput;
    },
    postToParent,
  });

  /**
   * Main message handler for iframe communication
   * This function receives all messages from the parent application and routes them
   * to the appropriate TatchiPasskey operations.
   */
  const onPortMessage = async (e: MessageEvent<ParentToChildEnvelope>) => {
    const req = e.data as ParentToChildEnvelope;
    if (!req || !isObject(req)) return;
    const requestId = req.requestId;

    // Handle ping/pong for connection health checks
    if (req.type === 'PING') {
      // Initialize TatchiPasskey and prewarm workers on wallet origin (non-blocking)
      if (ctx.walletConfigs?.nearRpcUrl && ctx.walletConfigs?.contractId) {
        Promise.resolve().then(() => {
          const pm = ensureTatchiPasskey();
          const pmAny = pm as unknown as { warmCriticalResources?: () => Promise<void> };
          if (pmAny?.warmCriticalResources) return pmAny.warmCriticalResources();
        }).catch(() => {});
      }
      post({ type: 'PONG', requestId });
      return;
    }

    // Handle configuration updates from parent
    if (req.type === 'PM_SET_CONFIG') {
      const payload = req.payload as PMSetConfigPayload;
      applyWalletConfig(ctx, payload);
      post({ type: 'PONG', requestId });
      return;
    }

    if (req.type === 'PM_CANCEL') {
      // Best-effort cancel: mark requestId and close any open modal inside the wallet host
      const rid = req.payload?.requestId;
      markCancelled(rid);
      // Cover all possible confirmation hosts used inside the wallet iframe
      const els = (CONFIRM_UI_ELEMENT_SELECTORS as readonly string[])
        .flatMap((sel) => Array.from(document.querySelectorAll(sel)) as HTMLElement[]);
      for (const el of els) {
        try {
          el.dispatchEvent(new CustomEvent(WalletIframeDomEvents.TX_CONFIRMER_CANCEL, { bubbles: true, composed: true }));
        } catch {}
      }
      if (rid) {
        // Immediately emit a terminal cancellation for the original request.
        // Handlers may also emit their own CANCELLED error; router tolerates duplicates.
        emitCancellationPayload(rid);
      }
      post({ type: 'PONG', requestId });
      return;
    }

    try {
      // Widen handler type for dynamic dispatch. HandlerMap is strongly typed at creation,
      // but when indexing with a runtime key, TS cannot correlate the specific envelope type.
      const handler = handlers[req.type as ParentToChildType] as unknown as (r: ParentToChildEnvelope) => Promise<void>;
      if (handler) {
        await handler(req);
      }
    } catch (err: unknown) {
      post({ type: 'ERROR', requestId, payload: { code: 'HOST_ERROR', message: errorMessage(err) } });
    }
  };

  addHostListeners(ctx, onPortMessage, PROTOCOL);
}

// Auto-init when this module is the entry bundle.
initWalletIFrame();
