import { IndexedDBManager } from '../core/IndexedDBManager';
import { toAccountId, type AccountId } from '../core/types/accountIds';
import type { DerivedAddressRecord } from '../core/IndexedDBManager';

function parseEip155ChainId(raw: unknown): string | null {
  const value = String(raw || '').trim().toLowerCase();
  if (!value) return null;
  if (/^\d+$/.test(value)) return value;
  if (!/^0x[0-9a-f]+$/.test(value)) return null;
  const asNumber = Number.parseInt(value, 16);
  if (!Number.isSafeInteger(asNumber) || asNumber < 0) return null;
  return String(asNumber);
}

function inferTargetChainIdFromPath(pathRaw: string): string {
  const path = String(pathRaw || '').trim().toLowerCase();
  const evmChainFromPath = (() => {
    const match = path.match(/^evm:([^:]+):/);
    return match?.[1] || null;
  })();
  if (path.startsWith('evm:')) {
    const chainId = parseEip155ChainId(evmChainFromPath || '');
    return chainId ? `eip155:${chainId}` : 'eip155:unknown';
  }
  if (path.startsWith('solana:')) return 'solana:unknown';
  if (path.startsWith('zcash:')) return 'zcash:unknown';
  if (path.startsWith('tempo:')) return 'tempo:unknown';
  return 'unknown:derived';
}

/**
 * DerivedAddressManager
 *
 * Encapsulates storage and retrieval of multi-chain derived addresses
 * for a given NEAR account. Uses the IndexedDB client DB under the hood
 * and supports path-encoded namespaces (e.g., `evm:<chainId>:<path>`).
 */
export class ChainsigAddressManager {
  async setDerivedAddress(
    nearAccountId: string | AccountId,
    args: { contractId: string; path: string; address: string }
  ): Promise<void> {
    const accountId = toAccountId(nearAccountId as string);
    const context = await IndexedDBManager.clientDB.resolveNearAccountContext(accountId).catch(() => null);
    if (!context) return;
    await IndexedDBManager.clientDB.setDerivedAddressV2({
      profileId: context.profileId,
      sourceChainId: context.sourceChainId,
      sourceAccountAddress: context.sourceAccountAddress,
      targetChainId: inferTargetChainIdFromPath(args.path),
      providerRef: args.contractId,
      path: args.path,
      address: args.address,
    });
  }

  async getDerivedAddressRecord(
    nearAccountId: string | AccountId,
    args: { contractId: string; path: string }
  ): Promise<DerivedAddressRecord | null> {
    const accountId = toAccountId(nearAccountId as string);
    const context = await IndexedDBManager.clientDB.resolveNearAccountContext(accountId).catch(() => null);
    if (!context) return null;
    const row = await IndexedDBManager.clientDB.getDerivedAddressV2({
      profileId: context.profileId,
      sourceChainId: context.sourceChainId,
      sourceAccountAddress: context.sourceAccountAddress,
      providerRef: args.contractId,
      path: args.path,
    });
    if (!row) return null;
    return {
      nearAccountId: accountId,
      contractId: row.providerRef,
      path: row.path,
      address: row.address,
      updatedAt: row.updatedAt,
    };
  }

  async getDerivedAddress(
    nearAccountId: string | AccountId,
    args: { contractId: string; path: string }
  ): Promise<string | null> {
    const rec = await this.getDerivedAddressRecord(nearAccountId, args);
    return rec?.address || null;
  }
}

export const chainsigAddressManager = new ChainsigAddressManager();
