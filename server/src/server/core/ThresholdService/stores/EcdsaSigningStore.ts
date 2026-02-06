import { toOptionalTrimmedString } from '@shared/utils/validation';

export type ThresholdEcdsaSigningSessionRecord = {
  expiresAtMs: number;
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
  userId: string;
  rpId: string;
  clientVerifyingShareB64u: string;
  participantIds: number[];
  presignatureId: string;
  entropyB64u: string;
  bigRB64u?: string;
};

export type ThresholdEcdsaPresignatureRelayerShareRecord = {
  relayerKeyId: string;
  presignatureId: string;
  bigRB64u: string;
  /** Base64url-encoded scalar share for k^{-1}. */
  kShareB64u: string;
  /** Base64url-encoded scalar share for x*k^{-1}. */
  sigmaShareB64u: string;
  createdAtMs: number;
};

export interface ThresholdEcdsaSigningSessionStore {
  putSigningSession(id: string, record: ThresholdEcdsaSigningSessionRecord, ttlMs: number): Promise<void>;
  takeSigningSession(id: string): Promise<ThresholdEcdsaSigningSessionRecord | null>;
}

export interface ThresholdEcdsaPresignaturePool {
  reserve(relayerKeyId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null>;
  consume(relayerKeyId: string, presignatureId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null>;
  discard(relayerKeyId: string, presignatureId: string): Promise<void>;
  put(record: ThresholdEcdsaPresignatureRelayerShareRecord): Promise<void>;
}

export class InMemoryThresholdEcdsaSigningSessionStore implements ThresholdEcdsaSigningSessionStore {
  private readonly map = new Map<string, { value: ThresholdEcdsaSigningSessionRecord; expiresAtMs: number }>();

  async putSigningSession(id: string, record: ThresholdEcdsaSigningSessionRecord, ttlMs: number): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing signingSessionId');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: record, expiresAtMs });
  }

  async takeSigningSession(id: string): Promise<ThresholdEcdsaSigningSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const entry = this.map.get(key);
    this.map.delete(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) return null;
    return entry.value;
  }
}

export class InMemoryThresholdEcdsaPresignaturePool implements ThresholdEcdsaPresignaturePool {
  private readonly availableByKey = new Map<string, ThresholdEcdsaPresignatureRelayerShareRecord[]>();
  private readonly reservedByKey = new Map<string, Map<string, { value: ThresholdEcdsaPresignatureRelayerShareRecord; expiresAtMs: number }>>();
  private readonly reservationTtlMs: number;

  constructor(input?: { reservationTtlMs?: number }) {
    this.reservationTtlMs = Math.max(1, Math.floor(Number(input?.reservationTtlMs) || 120_000));
  }

  private gc(relayerKeyId: string): void {
    const reserved = this.reservedByKey.get(relayerKeyId);
    if (!reserved) return;
    const now = Date.now();
    for (const [id, entry] of reserved.entries()) {
      if (now > entry.expiresAtMs) reserved.delete(id);
    }
    if (reserved.size === 0) this.reservedByKey.delete(relayerKeyId);
  }

  async put(record: ThresholdEcdsaPresignatureRelayerShareRecord): Promise<void> {
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const presignatureId = toOptionalTrimmedString(record.presignatureId);
    if (!relayerKeyId || !presignatureId) throw new Error('Missing relayerKeyId/presignatureId');

    const list = this.availableByKey.get(relayerKeyId) || [];
    list.push(record);
    this.availableByKey.set(relayerKeyId, list);
  }

  async reserve(relayerKeyId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    if (!key) return null;
    this.gc(key);
    const list = this.availableByKey.get(key);
    if (!list || list.length === 0) return null;
    const record = list.shift()!;
    this.availableByKey.set(key, list);

    let reserved = this.reservedByKey.get(key);
    if (!reserved) {
      reserved = new Map();
      this.reservedByKey.set(key, reserved);
    }
    reserved.set(record.presignatureId, { value: record, expiresAtMs: Date.now() + this.reservationTtlMs });
    return record;
  }

  async consume(relayerKeyId: string, presignatureId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    this.gc(key);
    const reserved = this.reservedByKey.get(key);
    if (!reserved) return null;
    const entry = reserved.get(id) || null;
    reserved.delete(id);
    if (reserved.size === 0) this.reservedByKey.delete(key);
    return entry?.value || null;
  }

  async discard(relayerKeyId: string, presignatureId: string): Promise<void> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return;
    this.gc(key);
    const reserved = this.reservedByKey.get(key);
    reserved?.delete(id);
    if (reserved && reserved.size === 0) this.reservedByKey.delete(key);
  }
}
