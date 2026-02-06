import type { ChildToParentEnvelope } from '../../shared/messages';
import { isIframeLoaded, trackIframeLoad } from './iframe-transport-dom';

export type HandshakeScheduler = {
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
};

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function createAbortError(): Error {
  return new Error('Wallet iframe connect aborted');
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw createAbortError();
  }
}

function createAbortPromise(signal?: AbortSignal): Promise<never> | null {
  if (!signal) return null;
  if (signal.aborted) return Promise.reject(createAbortError());
  return new Promise((_, reject) => {
    signal.addEventListener('abort', () => reject(createAbortError()), { once: true });
  });
}

export async function waitForLoad(iframe: HTMLIFrameElement, debug: boolean, signal?: AbortSignal): Promise<void> {
  if (isIframeLoaded(iframe)) return;
  trackIframeLoad(iframe);
  await new Promise<void>((resolve, reject) => {
    let done = false;
    let abortListener: (() => void) | null = null;
    const finish = () => {
      if (done) return;
      done = true;
      if (abortListener && signal) {
        signal.removeEventListener('abort', abortListener);
      }
      resolve();
    };
    const abort = () => {
      if (done) return;
      done = true;
      if (abortListener && signal) {
        signal.removeEventListener('abort', abortListener);
      }
      reject(createAbortError());
    };
    const timeout = window.setTimeout(() => {
      if (!done && debug) {
        console.debug('[IframeTransport] waitForLoad did not observe load event within 150ms; continuing');
      }
      finish();
    }, 150);
    iframe.addEventListener('load', () => {
      clearTimeout(timeout);
      finish();
    }, { once: true });
    if (signal) {
      abortListener = () => {
        clearTimeout(timeout);
        abort();
      };
      if (signal.aborted) {
        abortListener();
      } else {
        signal.addEventListener('abort', abortListener, { once: true });
      }
    }
  });
}

export async function waitForBootHint(
  isBooted: () => boolean,
  timeoutMs: number,
  signal?: AbortSignal,
  scheduler?: HandshakeScheduler,
): Promise<void> {
  if (isBooted() || timeoutMs <= 0) return;
  const now = scheduler?.now ?? Date.now;
  const sleep = scheduler?.sleep ?? defaultSleep;
  const start = now();
  while (!isBooted() && (now() - start) < timeoutMs) {
    throwIfAborted(signal);
    await sleep(50);
  }
}

type HandshakeOptions = {
  iframe: HTMLIFrameElement;
  connectTimeoutMs: number;
  walletOrigin: string;
  walletServiceUrl: URL;
  connectType: string;
  readyType: string;
  getTargetOrigin: (attempt: number) => string;
  scheduler?: HandshakeScheduler;
  signal?: AbortSignal;
};

export async function performHandshake(opts: HandshakeOptions): Promise<MessagePort> {
  const now = opts.scheduler?.now ?? Date.now;
  const sleep = opts.scheduler?.sleep ?? defaultSleep;
  const start = now();
  const abortPromise = createAbortPromise(opts.signal);
  let resolved = false;
  let attempt = 0;
  let warnedNullOrigin = false;

  let resolveReady!: (port: MessagePort) => void;
  let rejectReady!: (err: Error) => void;
  const readyPromise = new Promise<MessagePort>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });

  const resolveOnce = (port: MessagePort) => {
    if (resolved) return;
    resolved = true;
    resolveReady(port);
  };

  const rejectOnce = (err: Error) => {
    if (resolved) return;
    resolved = true;
    rejectReady(err);
  };

  while (!resolved) {
    throwIfAborted(opts.signal);
    const elapsed = now() - start;
    if (elapsed >= opts.connectTimeoutMs) {
      console.debug('[IframeTransport] handshake timeout after %d ms', elapsed);
      rejectOnce(new Error('Wallet iframe READY timeout'));
      break;
    }

    attempt += 1;
    const channel = new MessageChannel();
    const port1 = channel.port1;
    const port2 = channel.port2;

    port1.onmessage = (e: MessageEvent<ChildToParentEnvelope>) => {
      const data = e.data;
      if (data.type === opts.readyType) {
        resolveOnce(port1);
      }
    };

    // Ensure the receiving side is actively listening before we post the CONNECT
    try { port1.start?.(); } catch {}

    const cw = opts.iframe.contentWindow;
    if (!cw) {
      rejectOnce(new Error('Wallet iframe window missing'));
      break;
    }
    // Use strict origin once the host is booted; allow a short wildcard window
    // to tolerate opaque/unstable origins and dev mismatches until READY arrives.
    const targetOrigin = opts.getTargetOrigin(attempt);
    warnedNullOrigin = postConnectMessage(
      cw,
      { type: opts.connectType },
      port2,
      targetOrigin,
      warnedNullOrigin,
      elapsed,
      attempt,
      opts.walletServiceUrl
    );

    const interval = attempt < 10 ? 200 : attempt < 20 ? 400 : 800;
    try {
      if (abortPromise) {
        await Promise.race([readyPromise, sleep(interval), abortPromise]);
      } else {
        await Promise.race([readyPromise, sleep(interval)]);
      }
    } catch (err) {
      const message = err instanceof Error ? err : new Error(String(err));
      rejectOnce(message);
      break;
    }
  }

  return await readyPromise;
}

function postConnectMessage(
  cw: Window,
  data: unknown,
  port2: MessagePort,
  targetOrigin: string,
  warnedNullOrigin: boolean,
  elapsed: number,
  attempt: number,
  walletServiceUrl: URL
): boolean {
  try {
    cw.postMessage(data, targetOrigin, [port2]);
    return warnedNullOrigin;
  } catch (e) {
    const message = e instanceof Error ? e.message ?? String(e) : String(e);
    if (!warnedNullOrigin && message.includes("'null'")) {
      warnedNullOrigin = true;
      console.warn('[IframeTransport] CONNECT blocked; iframe origin appears to be null. Check that %s is reachable and responds with Cross-Origin-Resource-Policy: cross-origin.', walletServiceUrl.toString());
    }
    // Attempt wildcard fallback and continue retries
    try { cw.postMessage(data, '*', [port2]); } catch {}
    console.debug('[IframeTransport] CONNECT attempt %d threw after %d ms; retrying.', attempt, elapsed);
    return warnedNullOrigin;
  }
}
