import { html, type PropertyValues } from 'lit';
import { LitElementWithProps } from '../LitElementWithProps';
import DrawerElement from '../Drawer';
// Tokens for this component now come from w3a-components.css host scoping.
// We no longer map full color sets from DARK_THEME/LIGHT_THEME here.
import { dispatchLitCancel, dispatchLitCopy } from '../lit-events';
import { ensureExternalStyles } from '../css/css-loader';
import type { ExportPrivateKeyDisplayEntry } from '../../../flow/types';

export type ExportViewerTheme = 'dark' | 'light';
export type ExportViewerVariant = 'drawer' | 'modal';

export class ExportPrivateKeyViewer extends LitElementWithProps {
  // Ensure drawer definition is kept/loaded in the child iframe runtime
  static keepDefinitions = [DrawerElement];
  static properties = {
    theme: { type: String },
    variant: { type: String },
    accountId: { type: String, attribute: 'account-id' },
    publicKey: { type: String, attribute: 'public-key' },
    privateKey: { type: String, attribute: 'private-key' },
    keys: { attribute: false },
    loading: { type: Boolean },
    errorMessage: { type: String },
    showCloseButton: { type: Boolean, attribute: 'show-close-button' },
  } as const;

  declare theme: ExportViewerTheme;
  declare variant: ExportViewerVariant;
  declare accountId?: string;
  declare publicKey?: string;
  declare privateKey?: string;
  declare keys?: ExportPrivateKeyDisplayEntry[];
  declare loading: boolean;
  declare errorMessage?: string;
  declare showCloseButton: boolean;
  private copiedFields = new Set<string>();
  private copyTimers = new Map<string, number>();
  // Styles gating to avoid FOUC under strict CSP (no inline styles)
  private _stylesReady = false;
  private _stylePromises: Promise<void>[] = [];
  private _stylesAwaiting: Promise<void> | null = null;

  // Static styles moved to external CSS (export-viewer.css) for strict CSP

  constructor() {
    super();
    this.theme = 'dark';
    this.variant = 'drawer';
    this.keys = undefined;
    this.loading = false;
    this.showCloseButton = false;
  }

  protected getComponentPrefix(): string { return 'export'; }

  protected createRenderRoot(): HTMLElement | DocumentFragment {
    // Prefer Shadow DOM to scope styles when constructable stylesheets are supported.
    // Fallback to light DOM for strict-CSP + legacy engines (document-level <link> will style it).
    const supportsConstructable =
      typeof ShadowRoot !== 'undefined'
      && 'adoptedStyleSheets' in ShadowRoot.prototype
      && 'replaceSync' in (CSSStyleSheet.prototype as any);
    const root = supportsConstructable ? super.createRenderRoot() : (this as unknown as HTMLElement);
    // Adopt export-viewer.css for structural + visual styles
    const p1 = ensureExternalStyles(root as ShadowRoot | DocumentFragment | HTMLElement, 'export-viewer.css', 'data-w3a-export-viewer-css');
    this._stylePromises.push(p1);
    p1.catch(() => {});
    // Also adopt token sheet so color/background vars are available even without host styles
    const p2 = ensureExternalStyles(root as ShadowRoot | DocumentFragment | HTMLElement, 'w3a-components.css', 'data-w3a-components-css');
    this._stylePromises.push(p2);
    p2.catch(() => {});
    // Ensure drawer structural styles are available before first paint to prevent transparent background
    const p3 = ensureExternalStyles(root as ShadowRoot | DocumentFragment | HTMLElement, 'drawer.css', 'data-w3a-drawer-css');
    this._stylePromises.push(p3);
    p3.catch(() => {});
    return root;
  }

  // Avoid FOUC: block first paint until external styles are applied
  protected shouldUpdate(_changed: Map<string | number | symbol, unknown>): boolean {
    if (this._stylesReady) return true;
    if (!this._stylesAwaiting) {
      const settle = Promise.all(this._stylePromises)
        .then(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
      this._stylesAwaiting = settle.then(() => { this._stylesReady = true; this.requestUpdate(); });
    }
    return false;
  }

  protected updated(changed: PropertyValues) {
    super.updated(changed);
    if (changed.has('theme')) this.updateTheme();
  }

  connectedCallback(): void {
    super.connectedCallback();
    this.updateTheme();
    // Prevent drawer drag initiation from content area so text can be selected
    this.addEventListener('pointerdown', this._stopDragStart as EventListener);
    this.addEventListener('mousedown', this._stopDragStart as EventListener);
    this.addEventListener('touchstart', this._stopDragStart as EventListener, { passive: false } as AddEventListenerOptions);
  }

  disconnectedCallback(): void {
    this.removeEventListener('pointerdown', this._stopDragStart as EventListener);
    this.removeEventListener('mousedown', this._stopDragStart as EventListener);
    this.removeEventListener('touchstart', this._stopDragStart as EventListener);
    for (const timeoutId of this.copyTimers.values()) {
      clearTimeout(timeoutId);
    }
    this.copyTimers.clear();
    super.disconnectedCallback();
  }

  private _stopDragStart = (e: Event) => {
    // Do not preventDefault to allow text selection, just stop bubbling to drawer
    e.stopPropagation();
  };

  private updateTheme() {
    // Reflect theme to document root so host-scoped tokens respond
    try {
      const docEl = this.ownerDocument?.documentElement as HTMLElement | undefined;
      if (docEl && this.theme) {
        docEl.setAttribute('data-w3a-theme', this.theme);
      }
    } catch {}
  }

  private fieldKey(index: number, type: 'publicKey' | 'privateKey'): string {
    return `${index}:${type}`;
  }

  private isCopied(index: number, type: 'publicKey' | 'privateKey'): boolean {
    return this.copiedFields.has(this.fieldKey(index, type));
  }

  private markCopied(index: number, type: 'publicKey' | 'privateKey'): void {
    const field = this.fieldKey(index, type);
    this.copiedFields.add(field);
    const existingTimer = this.copyTimers.get(field);
    if (typeof existingTimer === 'number') clearTimeout(existingTimer);
    const timer = window.setTimeout(() => {
      this.copiedFields.delete(field);
      this.copyTimers.delete(field);
      this.requestUpdate();
    }, 3000);
    this.copyTimers.set(field, timer);
  }

  private async copy(type: 'publicKey' | 'privateKey', value?: string, index: number = 0) {
    if (!value) return;
    try {
      this.ownerDocument?.defaultView?.focus?.();
      (this as unknown as HTMLElement).focus?.();
      let ok = false;
      try {
        await navigator.clipboard.writeText(value);
        ok = true;
      } catch (err) {
        // Fallback to legacy execCommand path when direct clipboard fails (e.g., document not focused)
        ok = this.legacyCopy(value);
        if (!ok) throw err;
      }
      if (ok) {
        dispatchLitCopy(this, { type, value });
      }
      this.markCopied(index, type);
      this.requestUpdate();
    } catch (e) {
      console.warn('Copy failed', e);
    }
  }

  private legacyCopy(text: string): boolean {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'w3a-offscreen';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }

  private renderMaskedPrivateKey(sk: string) {
    if (!sk) return html`<span class="muted">—</span>`;
    const prefix = 'ed25519:';
    let startText = '';
    let middleText = '';
    let endText = '';

    if (sk.startsWith(prefix)) {
      const after = sk.slice(prefix.length);
      const first6 = after.slice(0, 6);
      const midStart = prefix.length + 6;
      const midEnd = Math.max(midStart, sk.length - 6);
      startText = prefix + first6;
      middleText = sk.slice(midStart, midEnd);
      endText = sk.slice(-6);
    } else {
      const first6 = sk.slice(0, 6);
      const midStart = 6;
      const midEnd = Math.max(midStart, sk.length - 6);
      startText = first6;
      middleText = sk.slice(midStart, midEnd);
      endText = sk.slice(-6);
    }

    const masked = 'x'.repeat(middleText.length || 0);
    return html`<span>${startText}</span><span class="mask-chunk">${masked}</span><span>${endText}</span>`;
  }

  private resolveKeyEntries(): ExportPrivateKeyDisplayEntry[] {
    const provided = Array.isArray(this.keys) ? this.keys.filter((item) => {
      if (!item || typeof item !== 'object') return false;
      const publicKey = String((item as ExportPrivateKeyDisplayEntry).publicKey || '').trim();
      const privateKey = String((item as ExportPrivateKeyDisplayEntry).privateKey || '').trim();
      return !!publicKey || !!privateKey;
    }) : [];
    if (provided.length > 0) return provided;

    const publicKey = String(this.publicKey || '').trim();
    const privateKey = String(this.privateKey || '').trim();
    if (!publicKey && !privateKey) return [];

    return [{
      scheme: 'ed25519',
      label: 'NEAR Ed25519',
      publicKey,
      privateKey,
    }];
  }

  render() {
    const entries = this.resolveKeyEntries();
    return html`
      ${
        this.showCloseButton
        ? html`<button
          aria-label="Close"
          title="Close"
          class="close-btn"
          @click=${() => dispatchLitCancel(this)}
          >×</button>`
        : null
      }
      <div class="content">
        <h2 class="title">Exported Keys</h2>
        <div class="fields">
          <div class="field">
            <div class="field-label">Account ID</div>
            <div class="field-value">
              <span class="value">
                ${this.accountId ? this.accountId : html`<span class="muted">—</span>`}
              </span>
            </div>
          </div>
          ${
            entries.length
              ? entries.map((entry, index) => {
                const label = String(entry.label || '').trim()
                  || (entry.scheme === 'secp256k1' ? 'EVM secp256k1' : 'NEAR Ed25519');
                const publicKey = String(entry.publicKey || '').trim();
                const privateKey = String(entry.privateKey || '').trim();
                const address = String(entry.address || '').trim();
                return html`
                  <div class="key-card">
                    <div class="key-title">${label}</div>
                    ${
                      address
                        ? html`
                          <div class="field">
                            <div class="field-label">Address</div>
                            <div class="field-value">
                              <span class="value">${address}</span>
                            </div>
                          </div>
                        `
                        : null
                    }
                    <div class="field">
                      <div class="field-label">Public Key</div>
                      <div class="field-value">
                        <span class="value">
                          ${publicKey ? publicKey : html`<span class="muted">—</span>`}
                        </span>
                        <button
                          class="btn btn-surface ${this.isCopied(index, 'publicKey') ? 'copied' : ''}"
                          title="Copy"
                          ?disabled=${!publicKey}
                          @click=${() => this.copy('publicKey', publicKey, index)}
                        >
                          ${this.isCopied(index, 'publicKey') ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    </div>
                    <div class="field">
                      <div class="field-label">Private Key</div>
                      <div class="field-value">
                        <span class="value private-key">
                          ${this.loading
                            ? html`<span class="muted">Decrypting…</span>`
                            : this.renderMaskedPrivateKey(privateKey)}
                        </span>
                        <button
                          class="btn btn-surface ${this.isCopied(index, 'privateKey') ? 'copied' : ''}"
                          title="Copy"
                          ?disabled=${!privateKey || this.loading}
                          @click=${() => this.copy('privateKey', privateKey, index)}
                        >
                          ${this.isCopied(index, 'privateKey') ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    </div>
                  </div>
                `;
              })
              : html`
                <div class="field">
                  <div class="field-value">
                    <span class="muted">${this.loading ? 'Decrypting…' : 'No keys available'}</span>
                  </div>
                </div>
              `
          }
        </div>
        <div class="warning">
          Warning: your private keys grant full control of your account and funds.
          Keep it in a secret place.
        </div>
      </div>
    `;
  }
}

if (!customElements.get('w3a-export-key-viewer')) {
  customElements.define('w3a-export-key-viewer', ExportPrivateKeyViewer);
}

// Ensure DrawerElement is kept by bundlers (used as container in iframe bootstrap)
export default ExportPrivateKeyViewer;
