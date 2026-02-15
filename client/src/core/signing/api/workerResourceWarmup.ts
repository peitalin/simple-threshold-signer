import type { UnifiedIndexedDBManager } from '../../IndexedDBManager';
import type { NearClient } from '../../near/NearClient';
import type { NonceManager } from '../../near/nonceManager';
import { toAccountId, type AccountId } from '../../types/accountIds';
import { getLastLoggedInDeviceNumber } from '../webauthn/device/getDeviceNumber';

export type WorkerResourceWarmupDeps = {
  workerBaseOrigin: string;
  indexedDB: UnifiedIndexedDBManager;
  nearClient: NearClient;
  nonceManager: Pick<NonceManager, 'prefetchBlockheight'>;
  preWarmWorkerPool: () => Promise<void>;
  initializeCurrentUser: (nearAccountId: AccountId, nearClient?: NearClient) => Promise<void>;
};

export function prewarmSignerWorkers(deps: WorkerResourceWarmupDeps): void {
  if (typeof window === 'undefined' || typeof (window as any).Worker === 'undefined') return;
  // Avoid noisy SecurityError in cross-origin dev: only prewarm when same-origin.
  if (deps.workerBaseOrigin && deps.workerBaseOrigin !== window.location.origin) return;
  deps.preWarmWorkerPool().catch(() => {});
}

export async function warmCriticalResources(
  deps: WorkerResourceWarmupDeps,
  nearAccountId?: string,
): Promise<void> {
  // Initialize current user first (best-effort).
  if (nearAccountId) {
    await deps.initializeCurrentUser(toAccountId(nearAccountId), deps.nearClient).catch(() => null);
  }

  // Prefetch latest block/nonce context (best-effort).
  await deps.nonceManager.prefetchBlockheight(deps.nearClient).catch(() => null);

  // Best-effort: open IndexedDB and warm key data for the account.
  if (nearAccountId) {
    const accountId = toAccountId(nearAccountId);
    const deviceNumber = await getLastLoggedInDeviceNumber(accountId, deps.indexedDB.clientDB).catch(
      () => 1,
    );
    await Promise.all([
      deps.indexedDB.getNearLocalKeyMaterialV2First(accountId, deviceNumber),
      deps.indexedDB.getNearThresholdKeyMaterialV2First(accountId, deviceNumber),
    ]).catch(() => null);
  }

  // Warm signer workers in the background.
  prewarmSignerWorkers(deps);
}
