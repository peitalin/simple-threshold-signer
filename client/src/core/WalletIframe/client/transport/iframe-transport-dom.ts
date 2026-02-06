import { ensureOverlayBase } from '../overlay/overlay-styles';
import { isDevHost } from '../../shared/is-dev-host';

const loadedIframes = new WeakSet<HTMLIFrameElement>();

export type IframeTestOptions = { routerId?: string; ownerTag?: string };

export function markIframeLoaded(iframe: HTMLIFrameElement): void {
  loadedIframes.add(iframe);
}

export function isIframeLoaded(iframe: HTMLIFrameElement): boolean {
  return loadedIframes.has(iframe);
}

export function trackIframeLoad(iframe: HTMLIFrameElement): void {
  if (isIframeLoaded(iframe)) return;
  iframe.addEventListener('load', () => markIframeLoaded(iframe), { once: true });
}

export function buildAllowAttr(walletOrigin: string): string {
  return `publickey-credentials-get 'self' ${walletOrigin}; publickey-credentials-create 'self' ${walletOrigin}; clipboard-read; clipboard-write`;
}

function isOverlayForOrigin(el: HTMLIFrameElement, walletOrigin: string): boolean {
  const dsOrigin = (el as { dataset?: { w3aOrigin?: string } }).dataset?.w3aOrigin;
  if (dsOrigin) return dsOrigin === walletOrigin;
  try {
    return new URL(el.src).origin === walletOrigin;
  } catch {
    return false;
  }
}

export function removeExistingOverlaysForOrigin(walletOrigin: string): void {
  if (typeof document === 'undefined') return;
  const existing = Array.from(document.querySelectorAll('iframe.w3a-wallet-overlay')) as HTMLIFrameElement[];
  const matches = existing.filter((el) => isOverlayForOrigin(el, walletOrigin));
  if (!matches.length) return;

  if (isDevHost()) {
    const routerIds = matches
      .map((el) => (el as { dataset?: { w3aRouterId?: string } }).dataset?.w3aRouterId)
      .filter((v): v is string => typeof v === 'string' && v.length > 0);
    console.warn(
      `[IframeTransport] Found existing wallet overlay iframe(s) for ${walletOrigin}. This usually indicates multiple SDK instances. Removing old iframe(s) to avoid duplicates.`,
      { count: matches.length, routerIds }
    );
  }

  for (const el of matches) {
    try { el.remove(); } catch {}
  }
}

export function createWalletIframe(opts: {
  walletOrigin: string;
  walletServiceUrl: URL;
  testOptions?: IframeTestOptions;
}): HTMLIFrameElement {
  const iframe = document.createElement('iframe');
  // Hidden by default via CSS classes; higher layers toggle state using overlay-styles.
  iframe.classList.add('w3a-wallet-overlay', 'is-hidden');
  // Ensure the base overlay stylesheet is installed early so computed styles
  // (opacity/pointer-events) reflect the hidden state immediately after mount.
  try { ensureOverlayBase(iframe); } catch {}
  // Ensure no initial footprint even before stylesheet attaches
  iframe.setAttribute('width', '0');
  iframe.setAttribute('height', '0');
  iframe.setAttribute('aria-hidden', 'true');
  iframe.setAttribute('tabindex', '-1');
  // Hint higher priority fetch for the iframe document on supporting browsers
  iframe.setAttribute('loading', 'eager');
  iframe.setAttribute('fetchpriority', 'high');

  iframe.dataset.w3aRouterId = opts.testOptions?.routerId || '';
  if (opts.testOptions?.ownerTag) iframe.dataset.w3aOwner = opts.testOptions.ownerTag;
  iframe.dataset.w3aOrigin = opts.walletOrigin;

  // Delegate WebAuthn + clipboard capabilities to the wallet origin frame
  try {
    iframe.setAttribute('allow', buildAllowAttr(opts.walletOrigin));
  } catch {
    iframe.setAttribute('allow', "publickey-credentials-get 'self'; publickey-credentials-create 'self'; clipboard-read; clipboard-write");
  }

  // Track load state to guard against races where we post before content is listening
  trackIframeLoad(iframe);

  const src = opts.walletServiceUrl.toString();
  console.debug('[IframeTransport] mount: external origin', src);
  iframe.src = src;

  document.body.appendChild(iframe);
  console.debug('[IframeTransport] mount: iframe appended');
  return iframe;
}
