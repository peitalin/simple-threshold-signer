import type { IDBPDatabase } from 'idb';
import type {
  EnqueueSignerOperationInput,
  SignerOperationStatus,
  SignerOpOutboxRecord,
} from '../passkeyClientDB.types';
import { SIGNER_OPS_OUTBOX_STATUS_NEXT_ATTEMPT_INDEX } from './schema';

function normalizeChainId(chainId: unknown): string {
  return String(chainId || '').trim().toLowerCase();
}

function normalizeAccountAddress(address: unknown): string {
  return String(address || '').trim().toLowerCase();
}

export function createSignerOperationId(prefix: string): string {
  return typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? `${prefix}:${crypto.randomUUID()}`
    : `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

export async function enqueueSignerOperationRecord(
  db: IDBPDatabase,
  signerOpsOutboxStore: string,
  input: EnqueueSignerOperationInput,
): Promise<SignerOpOutboxRecord> {
  const opId = String(input.opId || '').trim();
  const idempotencyKey = String(input.idempotencyKey || '').trim();
  const chainId = normalizeChainId(input.chainId);
  const accountAddress = normalizeAccountAddress(input.accountAddress);
  const signerId = String(input.signerId || '').trim();
  if (!opId || !idempotencyKey || !chainId || !accountAddress || !signerId) {
    throw new Error('PasskeyClientDB: opId, idempotencyKey, chainId, accountAddress, and signerId are required');
  }

  const now = Date.now();
  const existing = await db.get(signerOpsOutboxStore, opId) as SignerOpOutboxRecord | undefined;
  if (!existing) {
    const txByIdempotency = db.transaction(signerOpsOutboxStore, 'readonly');
    const byIdempotency = await txByIdempotency.store
      .index('idempotencyKey')
      .get(idempotencyKey) as SignerOpOutboxRecord | undefined;
    await txByIdempotency.done;
    if (byIdempotency) return byIdempotency;
  }

  const next: SignerOpOutboxRecord = {
    opId,
    idempotencyKey,
    opType: input.opType,
    chainId,
    accountAddress,
    signerId,
    payload: input.payload ?? existing?.payload,
    status: input.status ?? existing?.status ?? 'queued',
    attemptCount: input.attemptCount ?? existing?.attemptCount ?? 0,
    nextAttemptAt: input.nextAttemptAt ?? existing?.nextAttemptAt ?? now,
    lastError: input.lastError ?? existing?.lastError,
    txHash: input.txHash ?? existing?.txHash,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };

  try {
    await db.put(signerOpsOutboxStore, next);
  } catch (error: any) {
    const isConstraint = String(error?.name || '').toLowerCase() === 'constrainterror';
    if (!isConstraint) throw error;

    const txByIdempotency = db.transaction(signerOpsOutboxStore, 'readonly');
    const byIdempotency = await txByIdempotency.store
      .index('idempotencyKey')
      .get(idempotencyKey) as SignerOpOutboxRecord | undefined;
    await txByIdempotency.done;
    if (byIdempotency) return byIdempotency;
    throw error;
  }

  return next;
}

export async function listSignerOperationRecords(
  db: IDBPDatabase,
  signerOpsOutboxStore: string,
  args?: {
    statuses?: SignerOperationStatus[];
    dueBefore?: number;
    limit?: number;
  },
): Promise<SignerOpOutboxRecord[]> {
  const statuses = (args?.statuses && args.statuses.length > 0)
    ? args.statuses
    : (['queued', 'submitted', 'failed'] as SignerOperationStatus[]);
  const dueBeforeRaw = typeof args?.dueBefore === 'number' ? args.dueBefore : Date.now();
  const dueBefore = Number.isFinite(dueBeforeRaw) ? dueBeforeRaw : Number.MAX_SAFE_INTEGER;
  const limit = Number.isSafeInteger(args?.limit) && Number(args?.limit) > 0
    ? Number(args?.limit)
    : 100;

  const collected: SignerOpOutboxRecord[] = [];
  for (const status of statuses) {
    const tx = db.transaction(signerOpsOutboxStore, 'readonly');
    const rows = await tx.store
      .index(SIGNER_OPS_OUTBOX_STATUS_NEXT_ATTEMPT_INDEX)
      .getAll(
        IDBKeyRange.bound(
          [status, Number.MIN_SAFE_INTEGER],
          [status, dueBefore],
        ),
      ) as SignerOpOutboxRecord[];
    await tx.done;
    collected.push(...(rows || []));
  }

  collected.sort((a, b) => {
    const timeDelta = (a.nextAttemptAt || 0) - (b.nextAttemptAt || 0);
    if (timeDelta !== 0) return timeDelta;
    return String(a.opId || '').localeCompare(String(b.opId || ''));
  });

  return collected.slice(0, limit);
}

export async function setSignerOperationRecordStatus(
  db: IDBPDatabase,
  signerOpsOutboxStore: string,
  args: {
    opId: string;
    status: SignerOperationStatus;
    attemptDelta?: number;
    nextAttemptAt?: number;
    lastError?: string | null;
    txHash?: string | null;
  },
): Promise<SignerOpOutboxRecord | null> {
  const opId = String(args.opId || '').trim();
  if (!opId) return null;

  const existing = await db.get(signerOpsOutboxStore, opId) as SignerOpOutboxRecord | undefined;
  if (!existing) return null;

  const attemptDelta = Number.isFinite(args.attemptDelta) ? Number(args.attemptDelta) : 0;
  const attemptCount = Math.max(0, (existing.attemptCount || 0) + attemptDelta);
  const next: SignerOpOutboxRecord = {
    ...existing,
    status: args.status,
    attemptCount,
    nextAttemptAt:
      typeof args.nextAttemptAt === 'number'
        ? args.nextAttemptAt
        : existing.nextAttemptAt,
    ...(args.lastError === null
      ? { lastError: undefined }
      : (typeof args.lastError === 'string' ? { lastError: args.lastError } : { lastError: existing.lastError })),
    ...(args.txHash === null
      ? { txHash: undefined }
      : (typeof args.txHash === 'string' ? { txHash: args.txHash } : { txHash: existing.txHash })),
    updatedAt: Date.now(),
  };

  await db.put(signerOpsOutboxStore, next);
  return next;
}
