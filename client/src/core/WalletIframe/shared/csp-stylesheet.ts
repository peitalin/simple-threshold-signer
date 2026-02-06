type GlobalWithNonce = typeof window & { litNonce?: string; w3aNonce?: string };

type NonceSource = string | (() => string | undefined);

export type CspStylesheetManager = {
  ensureBase(): void;
  setDynamicRule(id: string, rule: string): void;
  deleteDynamicRule(id: string): void;
  clearDynamicRules(): void;
  hasDynamicRule(id: string): boolean;
};

export function getDefaultCspNonce(): string | undefined {
  if (typeof window === 'undefined') return undefined;
  const w = window as GlobalWithNonce;
  return w.w3aNonce || w.litNonce || undefined;
}

export function createCspStylesheetManager(opts: {
  doc: Document;
  baseCss: string;
  baseStyleDataAttr?: string;
  dynamicStyleDataAttr?: string;
  nonce?: NonceSource;
}): CspStylesheetManager {
  const { doc, baseCss, baseStyleDataAttr, dynamicStyleDataAttr, nonce } = opts;

  const state: {
    baseSheet: CSSStyleSheet | null;
    dynamicSheet: CSSStyleSheet | null;
    baseStyleEl: HTMLStyleElement | null;
    dynamicStyleEl: HTMLStyleElement | null;
    rules: Map<string, string>;
    supportConstructable: boolean | null;
  } = {
    baseSheet: null,
    dynamicSheet: null,
    baseStyleEl: null,
    dynamicStyleEl: null,
    rules: new Map(),
    supportConstructable: null,
  };

  const resolveNonce = (): string | undefined => {
    if (!nonce) return undefined;
    return typeof nonce === 'function' ? nonce() : nonce;
  };

  const supportsConstructable = (): boolean => {
    if (state.supportConstructable != null) return state.supportConstructable;
    state.supportConstructable = (typeof CSSStyleSheet !== 'undefined') && ('adoptedStyleSheets' in doc);
    return state.supportConstructable;
  };

  const adoptSheets = (sheets: CSSStyleSheet[]): void => {
    const current = (doc.adoptedStyleSheets || []) as CSSStyleSheet[];
    const next = [...current];
    for (const sheet of sheets) {
      if (!current.includes(sheet)) next.push(sheet);
    }
    doc.adoptedStyleSheets = next;
  };

  const appendStyleEl = (el: HTMLStyleElement): void => {
    const target = doc.head || doc.documentElement || doc.body;
    target?.appendChild(el);
  };

  const createStyleEl = (dataAttr?: string, cssText?: string): HTMLStyleElement => {
    const el = doc.createElement('style');
    const resolvedNonce = resolveNonce();
    if (resolvedNonce) {
      try { el.setAttribute('nonce', resolvedNonce); } catch {}
    }
    if (dataAttr) {
      try { el.setAttribute(dataAttr, ''); } catch {}
    }
    if (cssText != null) {
      el.textContent = cssText;
    }
    return el;
  };

  const ensureBase = (): void => {
    if (state.baseSheet || state.baseStyleEl) return;
    if (supportsConstructable()) {
      try {
        state.baseSheet = new CSSStyleSheet();
        state.baseSheet.replaceSync(baseCss);
        adoptSheets([state.baseSheet]);
        return;
      } catch {
        state.baseSheet = null;
        state.supportConstructable = false;
      }
    }
    const styleEl = createStyleEl(baseStyleDataAttr, baseCss);
    appendStyleEl(styleEl);
    state.baseStyleEl = styleEl;
  };

  const buildDynamicCss = (): string => Array.from(state.rules.values()).join('\n');

  const ensureDynamic = (): void => {
    if (supportsConstructable()) {
      if (!state.dynamicSheet) {
        state.dynamicSheet = new CSSStyleSheet();
        adoptSheets([state.dynamicSheet]);
      }
      return;
    }
    if (!state.dynamicStyleEl) {
      const el = createStyleEl(dynamicStyleDataAttr);
      appendStyleEl(el);
      state.dynamicStyleEl = el;
    }
  };

  const syncDynamic = (): void => {
    const css = buildDynamicCss();
    if (supportsConstructable()) {
      try {
        ensureDynamic();
        state.dynamicSheet?.replaceSync(css);
        return;
      } catch {
        state.supportConstructable = false;
        state.dynamicSheet = null;
      }
    }
    ensureDynamic();
    if (state.dynamicStyleEl) {
      state.dynamicStyleEl.textContent = css;
    }
  };

  return {
    ensureBase: () => {
      ensureBase();
    },
    setDynamicRule: (id: string, rule: string) => {
      ensureBase();
      state.rules.set(id, rule);
      syncDynamic();
    },
    deleteDynamicRule: (id: string) => {
      if (!state.rules.delete(id)) return;
      syncDynamic();
    },
    clearDynamicRules: () => {
      if (state.rules.size === 0) return;
      state.rules.clear();
      syncDynamic();
    },
    hasDynamicRule: (id: string) => state.rules.has(id),
  };
}
