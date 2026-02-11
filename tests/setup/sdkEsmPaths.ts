export const SDK_ESM_BASE_PATH = '/sdk/esm';

export function sdkEsmPath(subpath: string): string {
  const cleaned = String(subpath || '').replace(/^\/+/, '');
  return `${SDK_ESM_BASE_PATH}/${cleaned}`;
}

// Canonical browser-only dynamic imports from /sdk/esm/*
export const SDK_ESM_PATHS = {
  index: sdkEsmPath('index.js'),
  base64: sdkEsmPath('utils/base64.js'),
  accountIds: sdkEsmPath('core/types/accountIds.js'),
  actions: sdkEsmPath('core/types/actions.js'),
  tatchiPasskey: sdkEsmPath('core/TatchiPasskey/index.js'),
  walletIframeRouter: sdkEsmPath('core/WalletIframe/client/router.js'),
  confirmUi: sdkEsmPath('core/signing/secureConfirm/ui/lit-components/confirm-ui.js'),
  walletEvents: sdkEsmPath('core/WalletIframe/events.js'),
} as const;

export type SdkEsmPaths = typeof SDK_ESM_PATHS;

