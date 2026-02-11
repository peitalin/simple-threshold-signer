/**
 * IframeTransport - Client-Side Communication Layer
 *
 * This module handles the low-level iframe management and connection establishment.
 * It encapsulates all the complex browser-specific logic for safely creating and
 * connecting to the wallet service iframe.
 *
 * Key Responsibilities:
 * - Iframe Creation: Creates and mounts the iframe element with proper security attributes
 * - Security Hardening: Sets appropriate allow/sandbox attributes for WebAuthn and clipboard access
 * - Load Event Handling: Waits for iframe load to avoid postMessage races
 * - Connection Handshake: Performs robust CONNECT → READY handshake using MessageChannel
 * - Boot Latency Handling: Manages cross-origin boot delays with SERVICE_HOST_BOOTED hints
 * - Connection Deduplication: Prevents multiple concurrent connection attempts
 * - Error Handling: Provides clear error messages for connection failures
 *
 * Security Model:
 * - Uses explicit allow attributes for WebAuthn and clipboard permissions
 * - Avoids sandboxing for cross-origin deployments (prevents MessagePort transfer issues)
 * - Validates wallet origin URLs to prevent security issues
 * - Uses MessageChannel for secure, bidirectional communication
 *
 * Browser Compatibility:
 * - Handles various browser quirks around iframe loading and MessagePort transfer
 * - Provides fallback behavior for different browser implementations
 * - Manages timing issues with cross-origin iframe boot sequences
 */

import { isObject } from '../../../../../../shared/src/utils/validation';
import { WebAuthnBridgeMessage } from '../../../signing/webauthn/fallbacks';
import { createWalletIframe, removeExistingOverlaysForOrigin } from './iframe-transport-dom';
import { performHandshake, waitForBootHint, waitForLoad } from './iframe-transport-handshake';
import { handleWebAuthnBridgeMessage } from './webauthn-bridge';

const WILDCARD_CONNECT_ATTEMPTS = 6;

// Message constants (typed string literals, tree‑shake friendly)
export const IframeMessage = {
  Connect: 'CONNECT',
  Ready: 'READY',
  HostBooted: 'SERVICE_HOST_BOOTED',
  HostDebugOrigin: 'SERVICE_HOST_DEBUG_ORIGIN',
  HostLog: 'SERVICE_HOST_LOG',
} as const;

export interface IframeTransportOptions {
  walletOrigin: string;     // e.g., https://wallet.example.com
  servicePath?: string;      // default '/wallet-service'
  connectTimeoutMs?: number; // total budget for handshake retries
  debug?: boolean;           // enable verbose transport logging
  signal?: AbortSignal;      // optional cancellation signal for connect()
  testOptions?: {
    routerId?: string;         // identity tag for the iframe element
    ownerTag?: string;         // e.g., 'app' | 'tests'
  };
}

type ResolvedTransportOptions = Required<Omit<IframeTransportOptions, 'signal'>> & {
  signal?: AbortSignal;
};

export class IframeTransport {
  private readonly opts: ResolvedTransportOptions;
  private iframeEl: HTMLIFrameElement | null = null;
  private serviceBooted = false; // set when wallet host sends SERVICE_HOST_BOOTED (best-effort only)
  private connectInFlight: Promise<MessagePort> | null = null;
  private readonly walletServiceUrl: URL;
  private readonly walletOrigin: string;
  private readonly testOptions: { routerId?: string; ownerTag?: string };
  private debug = false;
  private readonly onWindowMessage = (e: MessageEvent): void => {
    const data = e.data as unknown;
    if (!isObject(data)) return;
    const type = (data as { type?: unknown }).type;
    if (type === IframeMessage.HostDebugOrigin) {
      if (this.debug) {
        console.debug('[IframeTransport][host-origin]', {
          origin: (data as { origin?: unknown }).origin,
          href: (data as { href?: unknown }).href,
          eventOrigin: e.origin,
        });
      }
      return;
    }
    if (e.origin !== this.walletOrigin) return;
    if (type === IframeMessage.HostBooted) {
      this.serviceBooted = true;
      return;
    }
    if (type === IframeMessage.HostLog) {
      if (this.debug) {
        console.debug('[IframeTransport][wallet-log]', (data as { payload?: unknown }).payload);
      }
      return;
    }
    if (type === WebAuthnBridgeMessage.Create || type === WebAuthnBridgeMessage.Get) {
      handleWebAuthnBridgeMessage(type as typeof WebAuthnBridgeMessage.Create | typeof WebAuthnBridgeMessage.Get, data, e);
    }
  };

  constructor(options: IframeTransportOptions) {
    this.opts = {
      servicePath: '/wallet-service',
      connectTimeoutMs: 8000,
      debug: false,
      ...options,
    } as ResolvedTransportOptions;

    try {
      this.walletServiceUrl = new URL(this.opts.servicePath, this.opts.walletOrigin);
    } catch (err) {
      throw new Error(`[IframeTransport] Invalid wallet origin (${options.walletOrigin}) or servicePath (${options.servicePath || '/wallet-service'})`);
    }
    this.walletOrigin = this.walletServiceUrl.origin;
    this.testOptions = {
      routerId: options.testOptions?.routerId,
      ownerTag: options.testOptions?.ownerTag,
    };
    this.debug = !!this.opts.debug;

    // Listen for a best-effort boot hint from the wallet host. Not required for correctness,
    // but helps reduce redundant CONNECT posts while the host script is still booting.
    if (typeof window !== 'undefined') {
      window.addEventListener('message', this.onWindowMessage);
    }
  }

  /** Returns the underlying iframe element if it exists. */
  getIframeEl(): HTMLIFrameElement | null { return this.iframeEl; }

  /** Remove global listeners created by this transport instance. */
  dispose(): void {
    if (typeof window !== 'undefined') {
      window.removeEventListener('message', this.onWindowMessage);
    }
  }

  /** Ensure the iframe element exists and is appended to the DOM. Idempotent. */
  ensureIframeMounted(): HTMLIFrameElement {
    if (this.iframeEl) {
      return this.iframeEl;
    }

    removeExistingOverlaysForOrigin(this.walletOrigin);
    const iframe = createWalletIframe({
      walletOrigin: this.walletOrigin,
      walletServiceUrl: this.walletServiceUrl,
      testOptions: this.testOptions,
    });
    this.iframeEl = iframe;
    return iframe;
  }

  /**
   * Connect to the wallet iframe using a MessageChannel handshake.
   * - Repeatedly posts {type:'CONNECT'} with a fresh port until a 'READY' message arrives
   * - Times out after connectTimeoutMs
   * - Deduplicates concurrent calls and returns the same MessagePort promise
   */
  async connect(): Promise<MessagePort> {
    if (this.connectInFlight) return this.connectInFlight;
    this.connectInFlight = (async () => {
      if (this.opts.signal?.aborted) {
        throw new Error('Wallet iframe connect aborted');
      }
      const iframe = this.ensureIframeMounted();

      // Ensure load fired at least once so the host script can attach listeners
      await waitForLoad(iframe, this.debug, this.opts.signal);

      // For cross-origin pages, give the host only a very brief moment to boot its script
      // Keep this low to avoid adding noticeable latency to the first CONNECT attempt.
      // The handshake will continue retrying regardless, so a shorter wait improves TTFB.
      const bootWaitMs = Math.min(this.opts.connectTimeoutMs / 12, 300);
      await waitForBootHint(() => this.serviceBooted, bootWaitMs, this.opts.signal);

      return performHandshake({
        iframe,
        connectTimeoutMs: this.opts.connectTimeoutMs,
        walletOrigin: this.walletOrigin,
        walletServiceUrl: this.walletServiceUrl,
        connectType: IframeMessage.Connect,
        readyType: IframeMessage.Ready,
        getTargetOrigin: (attempt) => this.getConnectTargetOrigin(attempt),
        signal: this.opts.signal,
      });
    })();

    try {
      return await this.connectInFlight;
    } finally {
      this.connectInFlight = null;
    }
  }

  private getConnectTargetOrigin(attempt: number): string {
    if (this.serviceBooted) return this.walletOrigin;
    if (attempt <= WILDCARD_CONNECT_ATTEMPTS) return '*';
    return this.walletOrigin;
  }
}
