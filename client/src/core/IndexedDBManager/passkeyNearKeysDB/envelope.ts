import type {
  PasskeyChainKeyMaterialV2,
  PasskeyChainKeyPayloadEnvelope,
  PasskeyChainKeyPayloadEnvelopeAAD,
} from '../passkeyNearKeysDB.types';
import { toTrimmedString } from '../../../../../shared/src/utils/validation';

export const KEY_PAYLOAD_ENC_VERSION = 1;
export const LOCAL_SK_ENVELOPE_ALG = 'chacha20poly1305-b64u-v1';

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function sanitizePayload(value: unknown): Record<string, unknown> | undefined {
  const record = asRecord(value);
  if (!record) return undefined;
  return { ...record };
}

export function buildEnvelopeAAD(args: {
  profileId: string;
  deviceNumber: number;
  chainId: string;
  keyKind: string;
  schemaVersion: number;
  signerId?: string;
}): PasskeyChainKeyPayloadEnvelopeAAD {
  const signerId = toTrimmedString(args.signerId || '');
  return {
    profileId: toTrimmedString(args.profileId || ''),
    deviceNumber: args.deviceNumber,
    chainId: toTrimmedString(args.chainId || '').toLowerCase(),
    keyKind: toTrimmedString(args.keyKind || ''),
    schemaVersion: args.schemaVersion,
    ...(signerId ? { signerId } : {}),
  };
}

function normalizeEnvelopeAAD(
  raw: unknown,
  expected: PasskeyChainKeyPayloadEnvelopeAAD,
  context: string,
): PasskeyChainKeyPayloadEnvelopeAAD {
  const record = asRecord(raw);
  const profileId = String(record?.profileId ?? expected.profileId).trim();
  const chainId = String(record?.chainId ?? expected.chainId).trim().toLowerCase();
  const keyKind = String(record?.keyKind ?? expected.keyKind).trim();
  const schemaVersionRaw = Number(record?.schemaVersion ?? expected.schemaVersion);
  const schemaVersion = Number.isSafeInteger(schemaVersionRaw) && schemaVersionRaw >= 1
    ? schemaVersionRaw
    : expected.schemaVersion;
  const deviceNumberRaw = Number(record?.deviceNumber ?? expected.deviceNumber);
  const deviceNumber = Number.isSafeInteger(deviceNumberRaw) && deviceNumberRaw >= 1
    ? deviceNumberRaw
    : expected.deviceNumber;
  const signerId = String(record?.signerId ?? expected.signerId ?? '').trim();
  const accountAddress = toTrimmedString(record?.accountAddress || '').toLowerCase();
  const normalized: PasskeyChainKeyPayloadEnvelopeAAD = {
    profileId,
    deviceNumber,
    chainId,
    keyKind,
    schemaVersion,
    ...(signerId ? { signerId } : {}),
    ...(accountAddress ? { accountAddress } : {}),
  };

  const matchesExpected =
    normalized.profileId === expected.profileId
    && normalized.deviceNumber === expected.deviceNumber
    && normalized.chainId === expected.chainId
    && normalized.keyKind === expected.keyKind
    && normalized.schemaVersion === expected.schemaVersion
    && (!expected.signerId || normalized.signerId === expected.signerId);
  if (!matchesExpected) {
    throw new Error(
      `PasskeyNearKeysDB: payloadEnvelope.aad mismatch for ${context}`,
    );
  }

  return normalized;
}

export function normalizePayloadEnvelope(
  raw: unknown,
  expectedAAD: PasskeyChainKeyPayloadEnvelopeAAD,
  context: string,
): PasskeyChainKeyPayloadEnvelope | undefined {
  if (raw == null) return undefined;
  const record = asRecord(raw);
  if (!record) {
    throw new Error(`PasskeyNearKeysDB: Invalid payloadEnvelope object for ${context}`);
  }
  const encVersionRaw = Number(record.encVersion);
  const encVersion = Number.isSafeInteger(encVersionRaw) && encVersionRaw >= 1
    ? encVersionRaw
    : NaN;
  const alg = toTrimmedString(record.alg || '');
  const nonce = toTrimmedString(record.nonce || '');
  const ciphertext = toTrimmedString(record.ciphertext || '');
  const tag = toTrimmedString(record.tag || '');
  if (!Number.isFinite(encVersion)) {
    throw new Error(`PasskeyNearKeysDB: Invalid payloadEnvelope.encVersion for ${context}`);
  }
  if (!alg || !nonce || !ciphertext) {
    throw new Error(`PasskeyNearKeysDB: Missing payloadEnvelope cryptographic fields for ${context}`);
  }
  return {
    encVersion,
    alg,
    nonce,
    ciphertext,
    ...(tag ? { tag } : {}),
    aad: normalizeEnvelopeAAD(record.aad, expectedAAD, context),
  };
}

function extractLegacyLocalSkPayload(payload: Record<string, unknown> | undefined): {
  encryptedSk: string;
  chacha20NonceB64u: string;
} | null {
  if (!payload) return null;
  const encryptedSk = toTrimmedString(payload.encryptedSk || '');
  const chacha20NonceB64u = toTrimmedString(payload.chacha20NonceB64u || '');
  if (!encryptedSk || !chacha20NonceB64u) return null;
  return { encryptedSk, chacha20NonceB64u };
}

function removeLegacyLocalSkPayloadFields(payload: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!payload) return undefined;
  const next = { ...payload };
  delete next.encryptedSk;
  delete next.chacha20NonceB64u;
  return Object.keys(next).length > 0 ? next : undefined;
}

export function hydrateCompatibilityPayload(rec: PasskeyChainKeyMaterialV2): PasskeyChainKeyMaterialV2 | null {
  const profileId = toTrimmedString(rec.profileId || '');
  const chainId = toTrimmedString(rec.chainId || '').toLowerCase();
  const keyKind = toTrimmedString(rec.keyKind || '');
  const algorithm = toTrimmedString(rec.algorithm || '');
  const publicKey = toTrimmedString(rec.publicKey || '');
  const signerId = toTrimmedString(rec.signerId || '');
  const wrapKeySalt = toTrimmedString(rec.wrapKeySalt || '');
  if (!profileId || !chainId || !keyKind || !algorithm || !publicKey) return null;
  if (!Number.isSafeInteger(rec.deviceNumber) || rec.deviceNumber < 1) return null;
  if (typeof rec.timestamp !== 'number') return null;
  if (!Number.isSafeInteger(rec.schemaVersion) || rec.schemaVersion < 1) return null;

  const payload = sanitizePayload(rec.payload);
  const expectedAAD = buildEnvelopeAAD({
    profileId,
    deviceNumber: rec.deviceNumber,
    chainId,
    keyKind,
    schemaVersion: rec.schemaVersion,
    ...(signerId ? { signerId } : {}),
  });
  const payloadEnvelope = normalizePayloadEnvelope(
    rec.payloadEnvelope,
    expectedAAD,
    `${profileId}/${rec.deviceNumber}/${chainId}/${keyKind}`,
  );

  if (keyKind === 'local_sk_encrypted_v1') {
    const legacyPayload = extractLegacyLocalSkPayload(payload);
    const encryptedSkFromEnvelope = toTrimmedString(payloadEnvelope?.ciphertext || '');
    const nonceFromEnvelope = toTrimmedString(payloadEnvelope?.nonce || '');
    const encryptedSk = String(legacyPayload?.encryptedSk || encryptedSkFromEnvelope).trim();
    const chacha20NonceB64u = String(legacyPayload?.chacha20NonceB64u || nonceFromEnvelope).trim();
    if (!encryptedSk || !chacha20NonceB64u) return null;
    if (
      legacyPayload
      && payloadEnvelope
      && (
        legacyPayload.encryptedSk !== encryptedSkFromEnvelope
        || legacyPayload.chacha20NonceB64u !== nonceFromEnvelope
      )
    ) {
      return null;
    }
    return {
      ...rec,
      profileId,
      chainId,
      keyKind,
      algorithm,
      publicKey,
      ...(signerId ? { signerId } : {}),
      ...(wrapKeySalt ? { wrapKeySalt } : {}),
      ...(payloadEnvelope ? { payloadEnvelope } : {}),
      payload: {
        ...(removeLegacyLocalSkPayloadFields(payload) || {}),
        encryptedSk,
        chacha20NonceB64u,
      },
    };
  }

  return {
    ...rec,
    profileId,
    chainId,
    keyKind,
    algorithm,
    publicKey,
    ...(signerId ? { signerId } : {}),
    ...(wrapKeySalt ? { wrapKeySalt } : {}),
    ...(payload ? { payload } : {}),
    ...(payloadEnvelope ? { payloadEnvelope } : {}),
  };
}

export function normalizeLocalSkEnvelope(args: {
  keyKind: string;
  payload: Record<string, unknown> | undefined;
  payloadEnvelope: PasskeyChainKeyPayloadEnvelope | undefined;
  expectedAAD: PasskeyChainKeyPayloadEnvelopeAAD;
}): {
  payload: Record<string, unknown> | undefined;
  payloadEnvelope: PasskeyChainKeyPayloadEnvelope | undefined;
} {
  if (args.keyKind !== 'local_sk_encrypted_v1') {
    return { payload: args.payload, payloadEnvelope: args.payloadEnvelope };
  }

  const legacyPayload = extractLegacyLocalSkPayload(args.payload);
  let payloadEnvelope = args.payloadEnvelope;
  if (!payloadEnvelope) {
    if (!legacyPayload) {
      throw new Error(
        'PasskeyNearKeysDB: local_sk_encrypted_v1 requires payloadEnvelope or legacy encryptedSk/chacha20NonceB64u payload fields',
      );
    }
    payloadEnvelope = {
      encVersion: KEY_PAYLOAD_ENC_VERSION,
      alg: LOCAL_SK_ENVELOPE_ALG,
      nonce: legacyPayload.chacha20NonceB64u,
      ciphertext: legacyPayload.encryptedSk,
      aad: args.expectedAAD,
    };
  } else if (
    legacyPayload
    && (
      legacyPayload.encryptedSk !== payloadEnvelope.ciphertext
      || legacyPayload.chacha20NonceB64u !== payloadEnvelope.nonce
    )
  ) {
    throw new Error(
      'PasskeyNearKeysDB: local_sk_encrypted_v1 payload and payloadEnvelope values must match',
    );
  }

  return {
    payload: removeLegacyLocalSkPayloadFields(args.payload),
    payloadEnvelope,
  };
}
