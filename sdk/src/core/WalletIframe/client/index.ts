/**
 * Wallet iframe client entrypoint.
 *
 * Typical flow:
 * 1) Create a WalletIframeRouter with options.
 * 2) Call init() to establish CONNECT/READY and push config to the host.
 */
import { WalletIframeRouter, type WalletIframeRouterOptions } from './router';

export * from './router';
export * from './env';

export async function initWalletIframeClient(
  options: WalletIframeRouterOptions
): Promise<WalletIframeRouter> {
  const router = new WalletIframeRouter(options);
  await router.init();
  return router;
}
