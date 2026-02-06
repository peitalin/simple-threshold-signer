/**
 * OverlayStyles - CSP-safe stylesheet manager for the wallet overlay iframe.
 *
 * Design goals:
 * - Zero inline style attributes (CSP style-src-attr 'none' compliant)
 * - Small, maintainable API: setHidden, setFullscreen, setAnchored
 * - Prefer constructable stylesheets; fall back to a nonce'd <style> for browsers
 *   without adoptedStyleSheets (mainly older Firefox/WebViews). Fallback is still
 *   important for broad compatibility unless you restrict supported browsers.
 */

import { createCspStylesheetManager, getDefaultCspNonce } from '../../shared/csp-stylesheet';

export type DOMRectLike = {
  top: number;
  left: number;
  width: number;
  height: number
};

const CLASS_BASE = 'w3a-wallet-overlay';
const CLASS_HIDDEN = 'is-hidden';
const CLASS_FULLSCREEN = 'is-fullscreen';
const CLASS_ANCHORED = 'is-anchored';

const BASE_CSS = `
  .${CLASS_BASE} { position: fixed; border: none; box-sizing: border-box; background: transparent; color-scheme: normal; transform: none; right: auto; bottom: auto; inset: auto; top: auto; left: auto; z-index: var(--w3a-wallet-overlay-z, 2147483646); }
  .${CLASS_BASE}.${CLASS_HIDDEN} { width: 0px; height: 0px; opacity: 0; pointer-events: none; z-index: auto; }
  .${CLASS_BASE}.${CLASS_FULLSCREEN} { top: 0; left: 0; right: 0; bottom: 0; inset: 0; opacity: 1; pointer-events: auto; }
  @supports (width: 100dvw) { .${CLASS_BASE}.${CLASS_FULLSCREEN} { width: 100dvw; height: 100dvh; } }
  @supports not (width: 100dvw) { .${CLASS_BASE}.${CLASS_FULLSCREEN} { width: 100vw; height: 100vh; } }
  .${CLASS_BASE}.${CLASS_ANCHORED} { opacity: 1; pointer-events: auto; }
`;

let styleManager: ReturnType<typeof createCspStylesheetManager> | null = null;
const getStyleManager = () => {
  if (!styleManager) {
    styleManager = createCspStylesheetManager({
      doc: document,
      baseCss: BASE_CSS,
      dynamicStyleDataAttr: 'data-w3a-overlay-dyn',
      nonce: () => getDefaultCspNonce(),
    });
  }
  return styleManager;
};

let overlayIdCounter = 0;
function asId(el: HTMLElement): string {
  if (el.id && el.id.startsWith('w3a-overlay-')) return el.id;
  const id = `w3a-overlay-${++overlayIdCounter}`;
  try { el.id = id; } catch {}
  return id;
}

export function ensureOverlayBase(el: HTMLElement): void {
  getStyleManager().ensureBase();
  try { el.classList.add(CLASS_BASE); } catch {}
}

export function setHidden(el: HTMLElement): void {
  ensureOverlayBase(el);
  try {
    el.classList.add(CLASS_HIDDEN);
    el.classList.remove(CLASS_FULLSCREEN);
    el.classList.remove(CLASS_ANCHORED);
  } catch {}
}

export function setFullscreen(el: HTMLElement): void {
  ensureOverlayBase(el);
  try {
    el.classList.add(CLASS_FULLSCREEN);
    el.classList.remove(CLASS_HIDDEN);
    el.classList.remove(CLASS_ANCHORED);
  } catch {}
}

export function setAnchored(el: HTMLElement, rect: DOMRectLike): void {
  ensureOverlayBase(el);
  const id = asId(el);
  const top = Math.max(0, Math.round(rect.top));
  const left = Math.max(0, Math.round(rect.left));
  const width = Math.max(1, Math.round(rect.width));
  const height = Math.max(1, Math.round(rect.height));
  const rule = `#${id}.${CLASS_ANCHORED}{ top:${top}px; left:${left}px; width:${width}px; height:${height}px; }`;
  getStyleManager().setDynamicRule(id, rule);

  try {
    el.classList.add(CLASS_ANCHORED);
    el.classList.remove(CLASS_HIDDEN);
    el.classList.remove(CLASS_FULLSCREEN);
  } catch {}
}

export function clearAnchoredRule(el: HTMLElement): void {
  if (!el?.id) return;
  getStyleManager().deleteDynamicRule(el.id);
}

export const OverlayStyleClasses = {
  BASE: CLASS_BASE,
  HIDDEN: CLASS_HIDDEN,
  FULLSCREEN: CLASS_FULLSCREEN,
  ANCHORED: CLASS_ANCHORED,
};
