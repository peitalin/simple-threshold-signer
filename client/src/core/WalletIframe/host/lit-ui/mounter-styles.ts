import { createCspStylesheetManager, getDefaultCspNonce } from '../../shared/csp-stylesheet';

/**
 * mounter-styles - CSP-safe stylesheet manager for wallet iframe host UI containers.
 * Replaces inline style attributes with classes + dynamic CSS rules.
 */

export type DOMRectLike = { top: number; left: number; width: number; height: number };

const CLASS_CONTAINER = 'w3a-host-container';
const CLASS_ELEMENT = 'w3a-host-element';
const CLASS_ANCHORED = 'is-anchored';
const BASE_CSS = `
  html, body { background: transparent; margin: 0; padding: 0; }
  .${CLASS_CONTAINER} { position: fixed; pointer-events: auto; background: transparent; border: 0; margin: 0; padding: 0; z-index: 2147483647; }
  .${CLASS_ELEMENT} { display: inline-block; }
`;

let styleManager: ReturnType<typeof createCspStylesheetManager> | null = null;
const getStyleManager = () => {
  if (!styleManager) {
    styleManager = createCspStylesheetManager({
      doc: document,
      baseCss: BASE_CSS,
      dynamicStyleDataAttr: 'data-w3a-host-dyn',
      nonce: () => getDefaultCspNonce(),
    });
  }
  return styleManager;
};

export function ensureHostBaseStyles(): void {
  getStyleManager().ensureBase();
}

let containerIdCounter = 0;
function ensureContainerId(el: HTMLElement): string {
  if (el.id && el.id.startsWith('w3a-host-')) {
    return el.id;
  }
  const id = `w3a-host-${++containerIdCounter}`;
  el.id = id;
  return id;
}

export function markContainer(el: HTMLElement): string {
  ensureHostBaseStyles();
  el.classList.add(CLASS_CONTAINER);
  el.dataset.w3aContainer = '1';
  return ensureContainerId(el);
}

export function setContainerAnchored(el: HTMLElement, rect: DOMRectLike, anchorMode: 'iframe' | 'viewport'): void {
  const id = markContainer(el);
  const top = anchorMode === 'iframe' ? 0 : Math.max(0, Math.round(rect.top));
  const left = anchorMode === 'iframe' ? 0 : Math.max(0, Math.round(rect.left));
  const width = Math.max(1, Math.round(rect.width));
  const height = Math.max(1, Math.round(rect.height));
  const rule = `#${id}.${CLASS_ANCHORED}{ top:${top}px; left:${left}px; width:${width}px; height:${height}px; }`;

  getStyleManager().setDynamicRule(id, rule);

  el.classList.add(CLASS_ANCHORED);
}

export function clearContainerRule(el: HTMLElement): void {
  if (!el?.id) return;
  getStyleManager().deleteDynamicRule(el.id);
}

export const HostMounterClasses = {
  CONTAINER: CLASS_CONTAINER,
  ELEMENT: CLASS_ELEMENT,
  ANCHORED: CLASS_ANCHORED,
};
