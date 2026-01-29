// Minimal shims to make import.meta.env references compile in various bundlers

interface ImportMeta {
  // Vite/Rollup inject an env object at build time
  readonly env?: Record<string, string>;
}

declare var process: { env?: Record<string, string | undefined> };

// Narrow globals used by the Wallet Iframe codepath
declare global {
  interface Window {
    // Absolute base URL for embedded SDK assets inside wallet host
    __W3A_WALLET_SDK_BASE__?: string;
  }
}

export {};
