import { IndexedDBManager } from '../../core/IndexedDBManager';
import type { AccountId } from '../../core/types/accountIds';
import type { PendingEmailRecovery } from '../../core/types/emailRecovery';

export interface PendingStore {
  get(accountId: AccountId, nearPublicKey?: string): Promise<PendingEmailRecovery | null>;
  set(record: PendingEmailRecovery): Promise<void>;
  clear(accountId: AccountId, nearPublicKey?: string): Promise<void>;
  touchIndex(accountId: AccountId, nearPublicKey: string): Promise<void>;
}

type EmailRecoveryPendingStoreOptions = {
  getPendingTtlMs: () => number;
  now?: () => number;
};

export class EmailRecoveryPendingStore implements PendingStore {
  private getPendingTtlMs: () => number;
  private now: () => number;

  constructor(options: EmailRecoveryPendingStoreOptions) {
    this.getPendingTtlMs = options.getPendingTtlMs;
    this.now = options.now ?? Date.now;
  }

  private getPendingIndexKey(accountId: AccountId): string {
    return `pendingEmailRecovery:${accountId}`;
  }

  private getPendingRecordKey(accountId: AccountId, nearPublicKey: string): string {
    return `${this.getPendingIndexKey(accountId)}:${nearPublicKey}`;
  }

  async get(accountId: AccountId, nearPublicKey?: string): Promise<PendingEmailRecovery | null> {
    const pendingTtlMs = this.getPendingTtlMs();
    const indexKey = this.getPendingIndexKey(accountId);
    const indexedNearPublicKey = await IndexedDBManager.clientDB.getAppState<string>(indexKey);
    const resolvedNearPublicKey = nearPublicKey ?? indexedNearPublicKey;
    if (!resolvedNearPublicKey) {
      return null;
    }

    const recordKey = this.getPendingRecordKey(accountId, resolvedNearPublicKey);
    const record = await IndexedDBManager.clientDB.getAppState<PendingEmailRecovery>(recordKey);
    const shouldClearIndex = indexedNearPublicKey === resolvedNearPublicKey;
    if (!record) {
      if (shouldClearIndex) {
        await IndexedDBManager.clientDB.setAppState(indexKey, undefined as any).catch(() => { });
      }
      return null;
    }

    if (this.now() - record.createdAt > pendingTtlMs) {
      await IndexedDBManager.clientDB.setAppState(recordKey, undefined as any).catch(() => { });
      if (shouldClearIndex) {
        await IndexedDBManager.clientDB.setAppState(indexKey, undefined as any).catch(() => { });
      }
      return null;
    }

    if (record.nearPublicKey) {
      await this.touchIndex(accountId, record.nearPublicKey);
    }
    return record;
  }

  async set(record: PendingEmailRecovery): Promise<void> {
    const nearPublicKey = record.nearPublicKey;
    if (!nearPublicKey) {
      throw new Error('[EmailRecoveryPendingStore] Missing nearPublicKey (required to persist pending record)');
    }
    const key = this.getPendingRecordKey(record.accountId, nearPublicKey);
    await IndexedDBManager.clientDB.setAppState(key, record);
    await this.touchIndex(record.accountId, nearPublicKey);
  }

  async clear(accountId: AccountId, nearPublicKey?: string): Promise<void> {
    const indexKey = this.getPendingIndexKey(accountId);
    const idx = await IndexedDBManager.clientDB.getAppState<string>(indexKey).catch(() => undefined);

    const resolvedNearPublicKey = nearPublicKey || idx || '';
    if (resolvedNearPublicKey) {
      await IndexedDBManager.clientDB
        .setAppState(this.getPendingRecordKey(accountId, resolvedNearPublicKey), undefined as any)
        .catch(() => { });
    }

    if (!nearPublicKey || idx === nearPublicKey) {
      await IndexedDBManager.clientDB.setAppState(indexKey, undefined as any).catch(() => { });
    }
  }

  async touchIndex(accountId: AccountId, nearPublicKey: string): Promise<void> {
    await IndexedDBManager.clientDB.setAppState(this.getPendingIndexKey(accountId), nearPublicKey).catch(() => { });
  }
}
