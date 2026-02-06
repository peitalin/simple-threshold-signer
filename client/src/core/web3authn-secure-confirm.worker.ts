/**
 * SecureConfirm Web Worker (VRF removed)
 *
 * This worker previously hosted the VRF WASM runtime. In the lite threshold-signer
 * refactor we remove VRF entirely, but keep the worker bundle as a home for the
 * SecureConfirm bridge (`awaitSecureConfirmationV2`).
 *
 * Why keep a dedicated worker?
 * - Preserves the existing worker/main-thread handshake used by confirmTxFlow.
 * - Keeps the wallet-origin confirmation surface isolated from app-origin code.
 */
import {
  awaitSecureConfirmationV2,
} from './WebAuthnManager/SecureConfirmWorkerManager/confirmTxFlow/awaitSecureConfirmation';
import { SecureConfirmMessageType } from './WebAuthnManager/SecureConfirmWorkerManager/confirmTxFlow/types';

// Expose the confirmation bridge under the JS name expected by wasm-bindgen.
// awaitSecureConfirmationV2 expects a SecureConfirmRequest object.
(globalThis as any).awaitSecureConfirmationV2 = awaitSecureConfirmationV2;

type ThresholdPrfFirstCacheEntry = {
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
};

type OkResult = { ok: true; remainingUses: number; expiresAtMs: number };
type OkDispenseResult = OkResult & { prfFirstB64u: string };
type ErrResult = { ok: false; code: string; message: string };

const prfFirstSessionCache = new Map<string, ThresholdPrfFirstCacheEntry>();

function nowMs(): number {
  return Date.now();
}

function normalizeSessionId(input: unknown): string {
  return typeof input === 'string' ? input.trim() : '';
}

function normalizeB64u(input: unknown): string {
  return typeof input === 'string' ? input.trim() : '';
}

function peekPrfFirstEntry(sessionId: string): OkResult | ErrResult {
  if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
  const entry = prfFirstSessionCache.get(sessionId);
  if (!entry) return { ok: false, code: 'not_found', message: 'PRF.first not cached for threshold session' };
  if (nowMs() >= entry.expiresAtMs) {
    prfFirstSessionCache.delete(sessionId);
    return { ok: false, code: 'expired', message: 'PRF.first cache expired for threshold session' };
  }
  if (entry.remainingUses <= 0) {
    prfFirstSessionCache.delete(sessionId);
    return { ok: false, code: 'exhausted', message: 'PRF.first cache exhausted for threshold session' };
  }
  return { ok: true, remainingUses: entry.remainingUses, expiresAtMs: entry.expiresAtMs };
}

function dispensePrfFirstEntry(sessionId: string, uses: number): OkDispenseResult | ErrResult {
  const peek = peekPrfFirstEntry(sessionId);
  if (!peek.ok) return peek;
  const entry = prfFirstSessionCache.get(sessionId);
  if (!entry) return { ok: false, code: 'not_found', message: 'PRF.first not cached for threshold session' };
  const usesNeeded = Math.max(1, Math.floor(Number(uses) || 1));
  if (entry.remainingUses < usesNeeded) {
    return { ok: false, code: 'exhausted', message: 'PRF.first cache exhausted for threshold session' };
  }
  entry.remainingUses -= usesNeeded;
  if (entry.remainingUses <= 0) {
    prfFirstSessionCache.delete(sessionId);
  } else {
    prfFirstSessionCache.set(sessionId, entry);
  }
  return { ok: true, prfFirstB64u: entry.prfFirstB64u, remainingUses: entry.remainingUses, expiresAtMs: entry.expiresAtMs };
}

function postSecureConfirmWorkerResponse(id: unknown, payload: { success: boolean; data?: unknown; error?: string }): void {
  const response = {
    ...(typeof id === 'string' && id.trim() ? { id: id.trim() } : {}),
    success: !!payload.success,
    ...(payload.data !== undefined ? { data: payload.data } : {}),
    ...(payload.error ? { error: payload.error } : {}),
  };
  try { self.postMessage(response); } catch {}
}

// This worker intentionally ignores USER_PASSKEY_CONFIRM_RESPONSE at the
// `onmessage` level so awaitSecureConfirmationV2's listener can consume it.
self.onmessage = (event: MessageEvent) => {
  const eventType = (event.data as any)?.type;
  if (eventType === SecureConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE) return;

  const id = (event.data as any)?.id;

  // Health check / liveness
  if (eventType === 'PING') {
    postSecureConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'THRESHOLD_PRF_FIRST_CACHE_PUT') {
    try {
      const payload = (event.data as any)?.payload as any;
      const sessionId = normalizeSessionId(payload?.sessionId);
      const prfFirstB64u = normalizeB64u(payload?.prfFirstB64u);
      const expiresAtMs = Math.floor(Number(payload?.expiresAtMs) || 0);
      const remainingUses = Math.floor(Number(payload?.remainingUses) || 0);
      if (!sessionId || !prfFirstB64u) {
        postSecureConfirmWorkerResponse(id, { success: true, data: { ok: false, code: 'invalid_args', message: 'Missing sessionId or prfFirstB64u' } satisfies ErrResult });
        return;
      }
      if (expiresAtMs <= nowMs() || remainingUses <= 0) {
        postSecureConfirmWorkerResponse(id, { success: true, data: { ok: false, code: 'invalid_args', message: 'Invalid expiresAtMs or remainingUses' } satisfies ErrResult });
        return;
      }
      prfFirstSessionCache.set(sessionId, { prfFirstB64u, expiresAtMs, remainingUses });
      postSecureConfirmWorkerResponse(id, { success: true, data: { ok: true, remainingUses, expiresAtMs } satisfies OkResult });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      postSecureConfirmWorkerResponse(id, { success: false, error: msg });
    }
    return;
  }

  if (eventType === 'THRESHOLD_PRF_FIRST_CACHE_PEEK') {
    const payload = (event.data as any)?.payload as any;
    const sessionId = normalizeSessionId(payload?.sessionId);
    postSecureConfirmWorkerResponse(id, { success: true, data: peekPrfFirstEntry(sessionId) });
    return;
  }

  if (eventType === 'THRESHOLD_PRF_FIRST_CACHE_DISPENSE') {
    const payload = (event.data as any)?.payload as any;
    const sessionId = normalizeSessionId(payload?.sessionId);
    const uses = Math.max(1, Math.floor(Number(payload?.uses) || 1));
    postSecureConfirmWorkerResponse(id, { success: true, data: dispensePrfFirstEntry(sessionId, uses) });
    return;
  }

  if (eventType === 'THRESHOLD_PRF_FIRST_CACHE_CLEAR') {
    const payload = (event.data as any)?.payload as any;
    const sessionId = normalizeSessionId(payload?.sessionId);
    if (sessionId) prfFirstSessionCache.delete(sessionId);
    postSecureConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  // Unknown message types: respond with an explicit error (prevents sendMessage timeouts).
  if (typeof id === 'string' && id.trim()) {
    postSecureConfirmWorkerResponse(id, { success: false, error: `Unsupported SecureConfirm worker message type: ${String(eventType)}` });
  }
};

// === GLOBAL ERROR MONITORING ===

self.onerror = (error) => {
  console.error('[secure-confirm-worker] error:', error);
};

self.onunhandledrejection = (event) => {
  console.error('[secure-confirm-worker] Unhandled promise rejection:', event.reason);
  event.preventDefault();
};
