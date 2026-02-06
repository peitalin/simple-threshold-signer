import type { NormalizedLogger } from '../logger';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { AccessKeyList } from '@/core/NearClient';
import type { ThresholdEd25519KeyStore } from './stores/KeyStore';
import type {
  ThresholdEd25519SessionStore,
} from './stores/SessionStore';
import type { ThresholdEcdsaPresignaturePool, ThresholdEcdsaSigningSessionStore } from './stores/EcdsaSigningStore';
import { InMemoryThresholdEcdsaPresignaturePool, InMemoryThresholdEcdsaSigningSessionStore } from './stores/EcdsaSigningStore';
import type {
  ThresholdEd25519AuthSessionStore,
  ThresholdEd25519AuthSessionRecord,
} from './stores/AuthSessionStore';
import type { ThresholdEd25519KeygenStrategy } from './keygenStrategy';
import { ThresholdEd25519KeygenStrategyV1 } from './keygenStrategy';
import type {
  VerifyAuthenticationResponse,
  ThresholdEd25519AuthorizeResponse,
  ThresholdEd25519SessionRequest,
  ThresholdEd25519SessionResponse,
  ThresholdEd25519AuthorizeWithSessionRequest,
  ThresholdEd25519KeygenRequest,
  ThresholdEd25519KeygenResponse,
  ThresholdEcdsaKeygenRequest,
  ThresholdEcdsaKeygenResponse,
  ThresholdEcdsaSessionRequest,
  ThresholdEcdsaSessionResponse,
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaAuthorizeResponse,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignFinalizeResponse,
  ThresholdEcdsaSignInitRequest,
  ThresholdEcdsaSignInitResponse,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519CosignInitResponse,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignFinalizeResponse,
  ThresholdEd25519SignInitRequest,
  ThresholdEd25519SignInitResponse,
  ThresholdEd25519SignFinalizeRequest,
  ThresholdEd25519SignFinalizeResponse,
  ThresholdEd25519KeyStoreConfigInput,
  WebAuthnAuthenticationCredential,
} from '../types';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { SECP256K1_ORDER } from '@shared/threshold/secp256k1';
import {
  threshold_ed25519_compute_delegate_signing_digest,
  threshold_ed25519_compute_near_tx_signing_digests,
  threshold_ed25519_compute_nep413_signing_digest,
} from '../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  ensureRelayerKeyIsActiveAccessKey,
  extractAuthorizeSigningPublicKey,
  isObject,
  normalizeByteArray32,
  type ThresholdEd25519SessionClaims,
  type ThresholdEcdsaSessionClaims,
  verifyThresholdEd25519AuthorizeSigningPayloadSigningDigestOnly,
} from './validation';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  normalizeThresholdEd25519ParticipantIds,
  normalizeThresholdEd25519ParticipantId,
} from '@shared/threshold/participants';
import type { ThresholdEd25519ShareMode } from './config';
import {
  coerceThresholdEd25519ShareMode,
  coerceThresholdNodeRole,
  parseThresholdCoordinatorSharedSecretBytes,
  parseThresholdEd25519ParticipantIds2p,
  parseThresholdRelayerCosignerThreshold,
  parseThresholdRelayerCosigners,
  validateThresholdEd25519MasterSecretB64u,
  validateThresholdSecp256k1MasterSecretB64u,
} from './config';
import { ThresholdEcdsaSigningHandlers } from './ecdsaSigningHandlers';
import { ThresholdEd25519SigningHandlers } from './signingHandlers';
import { resolveThresholdEd25519RelayerKeyMaterial, shouldUseDerivedRelayerShares } from './relayerKeyMaterial';
import type {
  ThresholdAnySchemeModule,
  ThresholdEd25519RegistrationKeygenRequest,
  ThresholdEd25519RegistrationKeygenResult,
} from './schemes/types';
import type { ThresholdSchemeId } from './schemes/schemeIds';
import {
  THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
  THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
} from './schemes/schemeIds';
import { createThresholdEd25519Frost2pSchemeModule } from './schemes/ed25519Frost2p';
import { createThresholdSecp256k1Ecdsa2pSchemeModule } from './schemes/secp256k1Ecdsa2p';

type ParseOk<T> = { ok: true; value: T };
type ParseErr = { ok: false; code: string; message: string };
type ParseResult<T> = ParseOk<T> | ParseErr;

type ParsedThresholdEd25519KeygenRequest =
  {
    kind: 'webauthn';
    nearAccountId: string;
    clientVerifyingShareB64u: string;
    rpId: string;
    keygenSessionId: string;
  };

function parseThresholdEd25519KeygenRequest(request: ThresholdEd25519KeygenRequest): ParseResult<ParsedThresholdEd25519KeygenRequest> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const nearAccountId = toOptionalTrimmedString(rec.nearAccountId);
  if (!nearAccountId) {
    return { ok: false, code: 'invalid_body', message: 'nearAccountId is required' };
  }
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
  }

  const rpId =
    toOptionalTrimmedString(rec.rpId)
    || toOptionalTrimmedString((rec as unknown as { rp_id?: unknown }).rp_id);
  if (!rpId) {
    return { ok: false, code: 'invalid_body', message: 'rpId is required' };
  }

  const keygenSessionId = toOptionalTrimmedString(rec.keygenSessionId);
  if (!keygenSessionId) {
    return { ok: false, code: 'invalid_body', message: 'keygenSessionId is required' };
  }

  return { ok: true, value: { kind: 'webauthn', nearAccountId, clientVerifyingShareB64u, rpId, keygenSessionId } };
}

function parseThresholdEcdsaKeygenRequest(request: ThresholdEcdsaKeygenRequest): ParseResult<{
  userId: string;
  clientVerifyingShareB64u: string;
  rpId: string;
  keygenSessionId: string;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const userId = toOptionalTrimmedString(rec.userId);
  if (!userId) {
    return { ok: false, code: 'invalid_body', message: 'userId is required' };
  }
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
  }
  const rpId =
    toOptionalTrimmedString(rec.rpId)
    || toOptionalTrimmedString((rec as unknown as { rp_id?: unknown }).rp_id);
  if (!rpId) {
    return { ok: false, code: 'invalid_body', message: 'rpId is required' };
  }
  const keygenSessionId = toOptionalTrimmedString(rec.keygenSessionId);
  if (!keygenSessionId) {
    return { ok: false, code: 'invalid_body', message: 'keygenSessionId is required' };
  }
  return { ok: true, value: { userId, clientVerifyingShareB64u, rpId, keygenSessionId } };
}

function parseThresholdEd25519AuthorizeWithSessionRequest(request: ThresholdEd25519AuthorizeWithSessionRequest): ParseResult<{
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  purpose: string;
  signingDigest32: Uint8Array;
  signingPayload: unknown;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
  if (!relayerKeyId) return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
  }
  const purpose = toOptionalTrimmedString(rec.purpose);
  if (!purpose) return { ok: false, code: 'invalid_body', message: 'purpose is required' };
  const signingDigest32 = normalizeByteArray32(rec.signing_digest_32);
  if (!signingDigest32) {
    return { ok: false, code: 'invalid_body', message: 'signing_digest_32 (32 bytes) is required for threshold authorization' };
  }
  return { ok: true, value: { relayerKeyId, clientVerifyingShareB64u, purpose, signingDigest32, signingPayload: rec.signingPayload } };
}

function parseThresholdEd25519SessionRequest(
  request: ThresholdEd25519SessionRequest,
  participantIds2p: number[],
): ParseResult<{
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  nearAccountId: string;
  rpId: string;
  sessionId: string;
  ttlMsRaw: number;
  remainingUsesRaw: number;
  policyParticipantIds: number[] | null;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
  if (!relayerKeyId) {
    return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
  }
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
  }

  const policyRaw = (rec as { sessionPolicy?: unknown }).sessionPolicy;
  if (!isObject(policyRaw)) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy (object) is required' };
  }
  const version = toOptionalTrimmedString((policyRaw as Record<string, unknown>).version);
  if (version !== 'threshold_session_v1') {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.version must be threshold_session_v1' };
  }
  const nearAccountId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).nearAccountId);
  const rpId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).rpId);
  const sessionId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).sessionId);
  const policyRelayerKeyId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).relayerKeyId);
  const ttlMsRaw = Number((policyRaw as Record<string, unknown>).ttlMs);
  const remainingUsesRaw = Number((policyRaw as Record<string, unknown>).remainingUses);
  if (!nearAccountId || !rpId || !sessionId || !policyRelayerKeyId) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy{nearAccountId,rpId,relayerKeyId,sessionId} are required' };
  }
  if (policyRelayerKeyId !== relayerKeyId) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.relayerKeyId must match relayerKeyId' };
  }

  const policyHasParticipantIds = Object.prototype.hasOwnProperty.call(policyRaw, 'participantIds');
  const policyParticipantIds = normalizeThresholdEd25519ParticipantIds((policyRaw as Record<string, unknown>).participantIds);
  if (policyHasParticipantIds && !policyParticipantIds) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.participantIds must be a non-empty array of positive integers' };
  }
  if (policyParticipantIds) {
    if (policyParticipantIds.length < 2) {
      return { ok: false, code: 'invalid_body', message: 'sessionPolicy.participantIds must contain at least 2 participant ids' };
    }
    for (const id of participantIds2p) {
      if (!policyParticipantIds.includes(id)) {
        return { ok: false, code: 'unauthorized', message: `sessionPolicy.participantIds must include server signer set (expected to include participantIds=[${participantIds2p.join(',')}])` };
      }
    }
  }

  if (!Number.isFinite(ttlMsRaw) || ttlMsRaw <= 0) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.ttlMs must be a positive number' };
  }
  if (!Number.isFinite(remainingUsesRaw) || remainingUsesRaw <= 0) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.remainingUses must be a positive number' };
  }

  return {
    ok: true,
    value: {
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId,
      rpId,
      sessionId,
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds: policyParticipantIds || null,
    },
  };
}

function parseThresholdEcdsaAuthorizeWithSessionRequest(request: ThresholdEcdsaAuthorizeWithSessionRequest): ParseResult<{
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  purpose: string;
  signingDigest32: Uint8Array;
  signingPayload: unknown;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
  if (!relayerKeyId) return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
  }
  const purpose = toOptionalTrimmedString(rec.purpose);
  if (!purpose) return { ok: false, code: 'invalid_body', message: 'purpose is required' };
  const signingDigest32 = normalizeByteArray32(rec.signing_digest_32);
  if (!signingDigest32) {
    return { ok: false, code: 'invalid_body', message: 'signing_digest_32 (32 bytes) is required for threshold authorization' };
  }
  return { ok: true, value: { relayerKeyId, clientVerifyingShareB64u, purpose, signingDigest32, signingPayload: rec.signingPayload } };
}

function parseThresholdEcdsaSessionRequest(
  request: ThresholdEcdsaSessionRequest,
  participantIds2p: number[],
): ParseResult<{
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  userId: string;
  rpId: string;
  sessionId: string;
  ttlMsRaw: number;
  remainingUsesRaw: number;
  policyParticipantIds: number[] | null;
}> {
  const rec = (request || {}) as unknown as Record<string, unknown>;
  const relayerKeyId = toOptionalTrimmedString(rec.relayerKeyId);
  if (!relayerKeyId) {
    return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
  }
  const clientVerifyingShareB64u = toOptionalTrimmedString(rec.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
  }

  const policyRaw = (rec as { sessionPolicy?: unknown }).sessionPolicy;
  if (!isObject(policyRaw)) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy (object) is required' };
  }
  const version = toOptionalTrimmedString((policyRaw as Record<string, unknown>).version);
  if (version !== 'threshold_session_v1') {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.version must be threshold_session_v1' };
  }
  const userId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).userId);
  const rpId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).rpId);
  const sessionId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).sessionId);
  const policyRelayerKeyId = toOptionalTrimmedString((policyRaw as Record<string, unknown>).relayerKeyId);
  const ttlMsRaw = Number((policyRaw as Record<string, unknown>).ttlMs);
  const remainingUsesRaw = Number((policyRaw as Record<string, unknown>).remainingUses);
  if (!userId || !rpId || !sessionId || !policyRelayerKeyId) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy{userId,rpId,relayerKeyId,sessionId} are required' };
  }
  if (policyRelayerKeyId !== relayerKeyId) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.relayerKeyId must match relayerKeyId' };
  }

  const policyHasParticipantIds = Object.prototype.hasOwnProperty.call(policyRaw, 'participantIds');
  const policyParticipantIds = normalizeThresholdEd25519ParticipantIds((policyRaw as Record<string, unknown>).participantIds);
  if (policyHasParticipantIds && !policyParticipantIds) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.participantIds must be a non-empty array of positive integers' };
  }
  if (policyParticipantIds) {
    if (policyParticipantIds.length < 2) {
      return { ok: false, code: 'invalid_body', message: 'sessionPolicy.participantIds must contain at least 2 participant ids' };
    }
    for (const id of participantIds2p) {
      if (!policyParticipantIds.includes(id)) {
        return { ok: false, code: 'unauthorized', message: `sessionPolicy.participantIds must include server signer set (expected to include participantIds=[${participantIds2p.join(',')}])` };
      }
    }
  }

  if (!Number.isFinite(ttlMsRaw) || ttlMsRaw <= 0) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.ttlMs must be a positive number' };
  }
  if (!Number.isFinite(remainingUsesRaw) || remainingUsesRaw <= 0) {
    return { ok: false, code: 'invalid_body', message: 'sessionPolicy.remainingUses must be a positive number' };
  }

  return {
    ok: true,
    value: {
      relayerKeyId,
      clientVerifyingShareB64u,
      userId,
      rpId,
      sessionId,
      ttlMsRaw,
      remainingUsesRaw,
      policyParticipantIds: policyParticipantIds || null,
    },
  };
}

export class ThresholdSigningService {
  private readonly logger: NormalizedLogger;
  private readonly keyStore: ThresholdEd25519KeyStore;
  private readonly sessionStore: ThresholdEd25519SessionStore;
  private readonly authSessionStore: ThresholdEd25519AuthSessionStore;
  private readonly ecdsaKeyStore: ThresholdEd25519KeyStore;
  private readonly ecdsaSessionStore: ThresholdEd25519SessionStore;
  private readonly ecdsaAuthSessionStore: ThresholdEd25519AuthSessionStore;
  private readonly clientParticipantId: number;
  private readonly relayerParticipantId: number;
  private readonly participantIds2p: number[];
  private readonly shareMode: ThresholdEd25519ShareMode;
  private readonly relayerMasterSecretB64u: string | null;
  private readonly useDerivedRelayerShares: boolean;
  private readonly secp256k1MasterSecretB64u: string | null;
  private readonly keygenStrategy: ThresholdEd25519KeygenStrategy;
  private readonly signingHandlers: ThresholdEd25519SigningHandlers;
  private readonly ecdsaSigningSessionStore: ThresholdEcdsaSigningSessionStore;
  private readonly ecdsaPresignaturePool: ThresholdEcdsaPresignaturePool;
  private readonly ecdsaSigningHandlers: ThresholdEcdsaSigningHandlers;
  private readonly ensureReady: () => Promise<void>;
  private readonly ensureSignerWasm: () => Promise<void>;
  private readonly verifyWebAuthnAuthenticationLite: ((
    request: {
      nearAccountId: string;
      rpId: string;
      expectedChallenge: string;
      webauthn_authentication: WebAuthnAuthenticationCredential;
    }
  ) => Promise<VerifyAuthenticationResponse>) | null;
  private readonly viewAccessKeyList: (accountId: string) => Promise<AccessKeyList>;
  private cachedSchemeModules: Partial<Record<ThresholdSchemeId, ThresholdAnySchemeModule>> | null = null;

  constructor(input: {
    logger: NormalizedLogger;
    keyStore: ThresholdEd25519KeyStore;
    sessionStore: ThresholdEd25519SessionStore;
    authSessionStore: ThresholdEd25519AuthSessionStore;
    ecdsaKeyStore: ThresholdEd25519KeyStore;
    ecdsaSessionStore: ThresholdEd25519SessionStore;
    ecdsaAuthSessionStore: ThresholdEd25519AuthSessionStore;
    config?: ThresholdEd25519KeyStoreConfigInput | null;
    ensureReady: () => Promise<void>;
    ensureSignerWasm: () => Promise<void>;
    verifyWebAuthnAuthenticationLite?: (request: {
      nearAccountId: string;
      rpId: string;
      expectedChallenge: string;
      webauthn_authentication: WebAuthnAuthenticationCredential;
    }) => Promise<VerifyAuthenticationResponse>;
    viewAccessKeyList: (accountId: string) => Promise<AccessKeyList>;
  }) {
    this.logger = input.logger;
    this.keyStore = input.keyStore;
    this.sessionStore = input.sessionStore;
    this.authSessionStore = input.authSessionStore;
    this.ecdsaKeyStore = input.ecdsaKeyStore;
    this.ecdsaSessionStore = input.ecdsaSessionStore;
    this.ecdsaAuthSessionStore = input.ecdsaAuthSessionStore;
    const cfg = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;

    const nodeRole = coerceThresholdNodeRole(cfg.THRESHOLD_NODE_ROLE);
    const coordinatorSharedSecretBytes =
      parseThresholdCoordinatorSharedSecretBytes(cfg.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U);
    const relayerCosigners = parseThresholdRelayerCosigners(cfg.THRESHOLD_ED25519_RELAYER_COSIGNERS) || [];
    const relayerCosignerThreshold = parseThresholdRelayerCosignerThreshold(cfg.THRESHOLD_ED25519_RELAYER_COSIGNER_T);
    const relayerCosignerIdRaw = cfg.THRESHOLD_ED25519_RELAYER_COSIGNER_ID;
    const relayerCosignerId =
      relayerCosignerIdRaw === undefined ? null : normalizeThresholdEd25519ParticipantId(relayerCosignerIdRaw);
    if (nodeRole === 'cosigner' && !relayerCosignerId) {
      throw new Error('THRESHOLD_ED25519_RELAYER_COSIGNER_ID is required when THRESHOLD_NODE_ROLE=cosigner');
    }

    const ids = parseThresholdEd25519ParticipantIds2p({
      THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID: cfg.THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID,
      THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID: cfg.THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID,
    });
    this.clientParticipantId = ids.clientParticipantId;
    this.relayerParticipantId = ids.relayerParticipantId;
    this.participantIds2p = ids.participantIds2p;

    this.shareMode = coerceThresholdEd25519ShareMode(cfg.THRESHOLD_ED25519_SHARE_MODE);
    this.relayerMasterSecretB64u = validateThresholdEd25519MasterSecretB64u(cfg.THRESHOLD_ED25519_MASTER_SECRET_B64U);
    if (this.shareMode === 'derived' && !this.relayerMasterSecretB64u) {
      throw new Error('threshold-ed25519 derived share mode requires THRESHOLD_ED25519_MASTER_SECRET_B64U');
    }
    this.useDerivedRelayerShares = shouldUseDerivedRelayerShares({
      shareMode: this.shareMode,
      relayerMasterSecretB64u: this.relayerMasterSecretB64u,
    });
    this.secp256k1MasterSecretB64u =
      validateThresholdSecp256k1MasterSecretB64u(cfg.THRESHOLD_SECP256K1_MASTER_SECRET_B64U);
    this.ensureReady = input.ensureReady;
    this.ensureSignerWasm = input.ensureSignerWasm;
    this.verifyWebAuthnAuthenticationLite = input.verifyWebAuthnAuthenticationLite || null;
    this.viewAccessKeyList = input.viewAccessKeyList;
    this.keygenStrategy = new ThresholdEd25519KeygenStrategyV1({
      useDerivedShares: this.useDerivedRelayerShares,
      relayerMasterSecretB64u: this.relayerMasterSecretB64u,
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      ensureSignerWasm: this.ensureSignerWasm,
    });
    this.signingHandlers = new ThresholdEd25519SigningHandlers({
      logger: this.logger,
      nodeRole,
      relayerCosigners,
      relayerCosignerThreshold,
      relayerCosignerId,
      coordinatorSharedSecretBytes,
      clientParticipantId: this.clientParticipantId,
      relayerParticipantId: this.relayerParticipantId,
      participantIds2p: this.participantIds2p,
      sessionStore: this.sessionStore,
      ensureReady: this.ensureReady,
      ensureSignerWasm: this.ensureSignerWasm,
      viewAccessKeyList: this.viewAccessKeyList,
      resolveRelayerKeyMaterial: (args) => this.resolveRelayerKeyMaterial(args),
    });

    this.ecdsaSigningSessionStore = new InMemoryThresholdEcdsaSigningSessionStore();
    this.ecdsaPresignaturePool = new InMemoryThresholdEcdsaPresignaturePool();
	    this.ecdsaSigningHandlers = new ThresholdEcdsaSigningHandlers({
	      logger: this.logger,
	      nodeRole,
	      participantIds2p: this.participantIds2p,
	      clientParticipantId: this.clientParticipantId,
	      relayerParticipantId: this.relayerParticipantId,
	      secp256k1MasterSecretB64u: this.secp256k1MasterSecretB64u,
	      sessionStore: this.ecdsaSessionStore,
	      signingSessionStore: this.ecdsaSigningSessionStore,
	      presignaturePool: this.ecdsaPresignaturePool,
	      ensureReady: this.ensureReady,
	      createSigningSessionId: () => this.createThresholdEcdsaSigningSessionId(),
	      createPresignSessionId: () => this.createThresholdEcdsaPresignSessionId(),
	    });
  }

  getSchemeModule(schemeId: ThresholdSchemeId): ThresholdAnySchemeModule | null {
    if (!this.cachedSchemeModules) this.cachedSchemeModules = {};
    const existing = this.cachedSchemeModules[schemeId];
    if (existing) return existing;

    const created: ThresholdAnySchemeModule | null = (() => {
      if (schemeId === THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
        return createThresholdEd25519Frost2pSchemeModule({
          keygen: (request) => this.ed25519Keygen(request),
          registrationKeygenFromClientVerifyingShare: (request) =>
            this.ed25519RegistrationKeygenFromClientVerifyingShare(request),
          session: (request) => this.ed25519Session(request),
          authorize: (input) => this.ed25519AuthorizeWithSession(input),
          protocol: {
            signInit: (request) => this.signingHandlers.thresholdEd25519SignInit(request),
            signFinalize: (request) => this.signingHandlers.thresholdEd25519SignFinalize(request),
            internalCosignInit: (request) => this.signingHandlers.thresholdEd25519CosignInit(request),
            internalCosignFinalize: (request) => this.signingHandlers.thresholdEd25519CosignFinalize(request),
          },
        });
      }
      if (schemeId === THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID) {
        return createThresholdSecp256k1Ecdsa2pSchemeModule({
          keygen: (request) => this.ecdsaKeygen(request),
          session: (request) => this.ecdsaSession(request),
          authorize: (input) => this.ecdsaAuthorizeWithSession(input),
          presign: {
            init: (input) => this.ecdsaSigningHandlers.thresholdEcdsaPresignInit(input),
            step: (input) => this.ecdsaSigningHandlers.thresholdEcdsaPresignStep(input),
          },
          protocol: {
            signInit: (request: ThresholdEcdsaSignInitRequest): Promise<ThresholdEcdsaSignInitResponse> =>
              this.ecdsaSigningHandlers.thresholdEcdsaSignInit(request),
            signFinalize: (request: ThresholdEcdsaSignFinalizeRequest): Promise<ThresholdEcdsaSignFinalizeResponse> =>
              this.ecdsaSigningHandlers.thresholdEcdsaSignFinalize(request),
          },
        });
      }
      return null;
    })();

    if (!created) return null;
    this.cachedSchemeModules[schemeId] = created;
    return created;
  }

	  private async resolveRelayerKeyMaterial(input: {
	    relayerKeyId: string;
	    nearAccountId: string;
	    rpId: string;
	    clientVerifyingShareB64u: string;
  }): Promise<
	    | { ok: true; publicKey: string; relayerSigningShareB64u: string; relayerVerifyingShareB64u: string }
	    | { ok: false; code: string; message: string }
	  > {
	    return await resolveThresholdEd25519RelayerKeyMaterial({
	      ...input,
	      shareMode: this.shareMode,
	      relayerMasterSecretB64u: this.relayerMasterSecretB64u,
	      keyStore: this.keyStore,
	      keygenStrategy: this.keygenStrategy,
	    });
	  }

  private clampSessionPolicy(input: { ttlMs: number; remainingUses: number }): { ttlMs: number; remainingUses: number } {
    const ttlMs = Math.max(0, Math.floor(Number(input.ttlMs) || 0));
    const remainingUses = Math.max(0, Math.floor(Number(input.remainingUses) || 0));
    // Hard caps (server-side). Session policy digest must be computed against these final values.
    const MAX_TTL_MS = 10 * 60_000;
    const MAX_USES = 20;
    return {
      ttlMs: Math.min(ttlMs, MAX_TTL_MS),
      remainingUses: Math.min(remainingUses, MAX_USES),
    };
  }

  private async computeSessionPolicyDigest32(policy: unknown): Promise<Uint8Array> {
    const json = alphabetizeStringify(policy);
    return await sha256BytesUtf8(json);
  }

  private async putAuthSessionRecord(input: {
    store: ThresholdEd25519AuthSessionStore;
    sessionId: string;
    record: ThresholdEd25519AuthSessionRecord;
    ttlMs: number;
    remainingUses: number;
  }): Promise<void> {
    await input.store.putSession(input.sessionId, input.record, {
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
    });
  }

  private createThresholdEd25519MpcSessionId(): string {
    const id = typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `mpc-${id}`;
  }

  private createThresholdEcdsaMpcSessionId(): string {
    const id = typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `ecdsa-mpc-${id}`;
  }

  private createThresholdEcdsaSigningSessionId(): string {
    const id = typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `ecdsa-sign-${id}`;
  }

  private createThresholdEcdsaPresignSessionId(): string {
    const id = typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `ecdsa-presign-${id}`;
  }

  private createThresholdEd25519SigningSessionId(): string {
    const id = typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `sign-${id}`;
  }

  private async ed25519RegistrationKeygenFromClientVerifyingShare(
    input: ThresholdEd25519RegistrationKeygenRequest
  ): Promise<ThresholdEd25519RegistrationKeygenResult> {
    try {
      await this.ensureReady();
      const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
      if (!nearAccountId) {
        return { ok: false, code: 'invalid_body', message: 'nearAccountId is required' };
      }
      const rpId = toOptionalTrimmedString(input.rpId);
      if (!rpId) {
        return { ok: false, code: 'invalid_body', message: 'rpId is required' };
      }
      const clientVerifyingShareB64u = toOptionalTrimmedString(input.clientVerifyingShareB64u);
      if (!clientVerifyingShareB64u) {
        return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
      }

      const keygen = await this.keygenStrategy.keygenFromClientVerifyingShare({
        nearAccountId,
        rpId,
        clientVerifyingShareB64u,
      });
      if (!keygen.ok) return keygen;
      const { keyMaterial } = keygen;

      if (!this.useDerivedRelayerShares) {
        await this.keyStore.put(keyMaterial.relayerKeyId, {
          publicKey: keyMaterial.publicKey,
          relayerSigningShareB64u: keyMaterial.relayerSigningShareB64u,
          relayerVerifyingShareB64u: keyMaterial.relayerVerifyingShareB64u,
        });
      }

      return {
        ok: true,
        clientParticipantId: this.clientParticipantId,
        relayerParticipantId: this.relayerParticipantId,
        participantIds: [...this.participantIds2p],
        relayerKeyId: keyMaterial.relayerKeyId,
        publicKey: keyMaterial.publicKey,
        relayerVerifyingShareB64u: keyMaterial.relayerVerifyingShareB64u,
      };
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Internal error');
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519Keygen(request: ThresholdEd25519KeygenRequest): Promise<ThresholdEd25519KeygenResponse> {
    try {
      const parsedRequest = parseThresholdEd25519KeygenRequest(request);
      if (!parsedRequest.ok) return parsedRequest;

      await this.ensureReady();

      const { nearAccountId, clientVerifyingShareB64u, rpId, keygenSessionId } = parsedRequest.value;
      const webauthnAuthentication = (request as unknown as { webauthn_authentication?: unknown }).webauthn_authentication;

      if (!this.verifyWebAuthnAuthenticationLite) {
        return { ok: false, code: 'not_configured', message: 'Lite WebAuthn verification is not configured on this server' };
      }

      const expectedIntentJson = alphabetizeStringify({
        version: 'threshold_keygen_v1',
        nearAccountId,
        rpId,
        keygenSessionId,
      });
      const expectedIntentDigest32 = await sha256BytesUtf8(expectedIntentJson);
      const expectedChallenge = base64UrlEncode(expectedIntentDigest32);

      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId,
        rpId,
        expectedChallenge,
        webauthn_authentication: webauthnAuthentication as any,
      });

      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

      const keygen = await this.keygenStrategy.keygenFromClientVerifyingShare({
        nearAccountId,
        rpId,
        clientVerifyingShareB64u,
      });
      if (!keygen.ok) return keygen;
      const { keyMaterial } = keygen;
      const publicKey = keyMaterial.publicKey;
      const relayerKeyId = keyMaterial.relayerKeyId;

      if (!this.useDerivedRelayerShares) {
        await this.keyStore.put(relayerKeyId, {
          publicKey,
          relayerSigningShareB64u: keyMaterial.relayerSigningShareB64u,
          relayerVerifyingShareB64u: keyMaterial.relayerVerifyingShareB64u,
        });
      }

      return {
        ok: true,
        clientParticipantId: this.clientParticipantId,
        relayerParticipantId: this.relayerParticipantId,
        participantIds: [...this.participantIds2p],
        relayerKeyId,
        publicKey,
        relayerVerifyingShareB64u: keyMaterial.relayerVerifyingShareB64u,
      };
    } catch (e: unknown) {
      this.logger?.error?.('thresholdEd25519Keygen failed:', e);
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Internal error');
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ecdsaKeygen(request: ThresholdEcdsaKeygenRequest): Promise<ThresholdEcdsaKeygenResponse> {
    try {
      const parsedRequest = parseThresholdEcdsaKeygenRequest(request);
      if (!parsedRequest.ok) return parsedRequest;

      await this.ensureReady();

      const { userId, clientVerifyingShareB64u, rpId, keygenSessionId } = parsedRequest.value;
      const webauthnAuthentication = (request as unknown as { webauthn_authentication?: unknown }).webauthn_authentication;

      if (!this.verifyWebAuthnAuthenticationLite) {
        return { ok: false, code: 'not_configured', message: 'Lite WebAuthn verification is not configured on this server' };
      }

      const expectedIntentJson = alphabetizeStringify({
        version: 'threshold_ecdsa_keygen_v1',
        userId,
        rpId,
        keygenSessionId,
      });
      const expectedIntentDigest32 = await sha256BytesUtf8(expectedIntentJson);
      const expectedChallenge = base64UrlEncode(expectedIntentDigest32);

      const verification = await this.verifyWebAuthnAuthenticationLite({
        // NOTE: current WebAuthn stores are keyed by nearAccountId; in the multichain model
        // `userId` should become the stable identifier used by the authenticator store.
        nearAccountId: userId,
        rpId,
        expectedChallenge,
        webauthn_authentication: webauthnAuthentication as any,
      });

      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

      if (!this.secp256k1MasterSecretB64u) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'threshold-secp256k1 keygen requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U',
        };
      }

      let clientVerifyingShareBytes: Uint8Array;
      try {
        clientVerifyingShareBytes = base64UrlDecode(clientVerifyingShareB64u);
      } catch {
        return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u must be valid base64url' };
      }
      if (clientVerifyingShareBytes.length !== 33) {
        return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)' };
      }

      let clientPoint: ReturnType<typeof secp256k1.Point.fromBytes>;
      try {
        clientPoint = secp256k1.Point.fromBytes(clientVerifyingShareBytes);
        clientPoint.assertValidity();
      } catch {
        return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is not a valid secp256k1 public key' };
      }

      const relayerKeyIdDigest32 = await sha256BytesUtf8(alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId,
        clientVerifyingShareB64u,
      }));
      const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;

      const masterSecretBytes = base64UrlDecode(this.secp256k1MasterSecretB64u);
      const relayerShareSaltV1 = new TextEncoder().encode('tatchi/lite/threshold-secp256k1-ecdsa/relayer-share:v1');
      const relayerShareInfo = new TextEncoder().encode(relayerKeyId);
      const okm64 = hkdf(sha256, masterSecretBytes, relayerShareSaltV1, relayerShareInfo, 64);
      const reduced = (bytesToNumberBE(okm64) % (SECP256K1_ORDER - 1n)) + 1n;
      const relayerSigningShare32 = numberToBytesBE(reduced, 32);
      const relayerVerifyingShareBytes = secp256k1.getPublicKey(relayerSigningShare32, true);
      const relayerVerifyingShareB64u = base64UrlEncode(relayerVerifyingShareBytes);

      const relayerPoint = secp256k1.Point.fromBytes(relayerVerifyingShareBytes);
      const groupPoint = clientPoint.add(relayerPoint);
      const groupPublicKeyBytes = groupPoint.toBytes(true);
      const groupPublicKeyB64u = base64UrlEncode(groupPublicKeyBytes);

      const groupPublicKeyUncompressed = groupPoint.toBytes(false);
      const pubNoPrefix = groupPublicKeyUncompressed.length === 65 ? groupPublicKeyUncompressed.slice(1) : groupPublicKeyUncompressed;
      const hash = keccak_256(pubNoPrefix);
      const addrBytes = hash.slice(-20);
      const ethereumAddress = `0x${Array.from(addrBytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;

      return {
        ok: true,
        participantIds: [...this.participantIds2p],
        relayerKeyId,
        groupPublicKeyB64u,
        ethereumAddress,
        relayerVerifyingShareB64u,
      };
    } catch (e: unknown) {
      this.logger?.error?.('thresholdEcdsaKeygen failed:', e);
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Internal error');
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ecdsaSession(request: ThresholdEcdsaSessionRequest): Promise<ThresholdEcdsaSessionResponse> {
    let context: Record<string, unknown> | null = null;
    try {
      const parsedRequest = parseThresholdEcdsaSessionRequest(request, this.participantIds2p);
      if (!parsedRequest.ok) return parsedRequest;
      const {
        relayerKeyId,
        clientVerifyingShareB64u,
        userId,
        rpId,
        sessionId,
        ttlMsRaw,
        remainingUsesRaw,
        policyParticipantIds,
      } = parsedRequest.value;
      context = { userId, rpId, relayerKeyId, sessionId };

      await this.ensureReady();

      if (!this.verifyWebAuthnAuthenticationLite) {
        return { ok: false, code: 'not_configured', message: 'Lite WebAuthn verification is not configured on this server' };
      }

      if (!this.secp256k1MasterSecretB64u) {
        return { ok: false, code: 'not_configured', message: 'threshold-ecdsa requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U' };
      }

      // Validate the client verifying share and bind relayerKeyId to it.
      let clientVerifyingShareBytes: Uint8Array;
      try {
        clientVerifyingShareBytes = base64UrlDecode(clientVerifyingShareB64u);
      } catch {
        return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u must be valid base64url' };
      }
      if (clientVerifyingShareBytes.length !== 33) {
        return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)' };
      }
      try {
        const point = secp256k1.Point.fromBytes(clientVerifyingShareBytes);
        point.assertValidity();
      } catch {
        return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is not a valid secp256k1 public key' };
      }

      const expectedRelayerKeyIdDigest32 = await sha256BytesUtf8(alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId,
        clientVerifyingShareB64u,
      }));
      const expectedRelayerKeyId = `secp-${base64UrlEncode(expectedRelayerKeyIdDigest32)}`;
      if (relayerKeyId !== expectedRelayerKeyId) {
        return { ok: false, code: 'unauthorized', message: 'relayerKeyId does not match clientVerifyingShareB64u binding' };
      }

      const { ttlMs, remainingUses } = this.clampSessionPolicy({ ttlMs: ttlMsRaw, remainingUses: remainingUsesRaw });
      const participantIds = policyParticipantIds || [...this.participantIds2p];
      const normalizedPolicy = {
        version: 'threshold_session_v1',
        userId,
        rpId,
        relayerKeyId,
        sessionId,
        ...(policyParticipantIds ? { participantIds: policyParticipantIds } : {}),
        ttlMs,
        remainingUses,
      };
      const sessionPolicyDigest32 = await this.computeSessionPolicyDigest32(normalizedPolicy);
      const expectedChallenge = base64UrlEncode(sessionPolicyDigest32);

      const existingSession = await this.ecdsaAuthSessionStore.getSession(sessionId);
      if (existingSession) {
        if (existingSession.userId !== userId) {
          return { ok: false, code: 'unauthorized', message: 'threshold sessionId already exists for a different user' };
        }
        if (existingSession.relayerKeyId !== relayerKeyId) {
          return { ok: false, code: 'unauthorized', message: 'threshold sessionId already exists for a different relayerKeyId' };
        }
        if (existingSession.rpId !== rpId) {
          return { ok: false, code: 'unauthorized', message: 'threshold sessionId already exists for a different rpId' };
        }
        const sameParticipantIds = existingSession.participantIds.length === participantIds.length
          && existingSession.participantIds.every((id, i) => id === participantIds[i]);
        if (!sameParticipantIds) {
          return { ok: false, code: 'unauthorized', message: 'threshold sessionId already exists for a different participant set' };
        }
        return {
          ok: true,
          sessionId,
          expiresAtMs: existingSession.expiresAtMs,
          expiresAt: new Date(existingSession.expiresAtMs).toISOString(),
          participantIds: existingSession.participantIds,
        };
      }

      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId: userId,
        rpId,
        expectedChallenge,
        webauthn_authentication: request.webauthn_authentication,
      });
      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

	      const expiresAtMs = Date.now() + ttlMs;
	      await this.putAuthSessionRecord({
	        store: this.ecdsaAuthSessionStore,
	        sessionId,
	        record: {
	          expiresAtMs,
	          relayerKeyId,
	          userId,
	          rpId,
	          participantIds,
	        },
	        ttlMs,
	        remainingUses,
	      });

      return {
        ok: true,
        sessionId,
        expiresAtMs,
        expiresAt: new Date(expiresAtMs).toISOString(),
        participantIds,
        remainingUses,
      };
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Internal error');
      this.logger?.error?.('[threshold-ecdsa] session mint failed', { message: msg, ...(context || {}) });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ecdsaAuthorizeWithSession(input: {
    claims: ThresholdEcdsaSessionClaims;
    request: ThresholdEcdsaAuthorizeWithSessionRequest;
  }): Promise<ThresholdEcdsaAuthorizeResponse> {
    try {
      const claims = input.claims;
      const sessionId = toOptionalTrimmedString(claims?.sessionId);
      if (!sessionId) return { ok: false, code: 'unauthorized', message: 'Missing threshold sessionId' };
      const userId = toOptionalTrimmedString(claims?.sub);
      if (!userId) return { ok: false, code: 'unauthorized', message: 'Missing threshold userId' };

      const tokenRelayerKeyId = toOptionalTrimmedString(claims?.relayerKeyId);
      const tokenRpId = toOptionalTrimmedString(claims?.rpId);
      if (!tokenRelayerKeyId || !tokenRpId) {
        return { ok: false, code: 'unauthorized', message: 'Invalid threshold session token claims' };
      }

      const parsedRequest = parseThresholdEcdsaAuthorizeWithSessionRequest(input.request);
      if (!parsedRequest.ok) return parsedRequest;
      const { relayerKeyId, clientVerifyingShareB64u, purpose, signingDigest32 } = parsedRequest.value;

      await this.ensureReady();

      if (!this.secp256k1MasterSecretB64u) {
        return { ok: false, code: 'not_configured', message: 'threshold-ecdsa requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U' };
      }

      if (relayerKeyId !== tokenRelayerKeyId) {
        return { ok: false, code: 'unauthorized', message: 'relayerKeyId does not match threshold session scope' };
      }

      const thresholdExpiresAtMs = claims.thresholdExpiresAtMs;
      if (Date.now() > thresholdExpiresAtMs) {
        return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
      }

      const participantIds = claims.participantIds;
      for (const id of this.participantIds2p) {
        if (!participantIds.includes(id)) {
          return {
            ok: false,
            code: 'unauthorized',
            message: `threshold session token does not include server signer set (expected to include participantIds=[${this.participantIds2p.join(',')}])`,
          };
        }
      }

      const consumed = await this.ecdsaAuthSessionStore.consumeUseCount(sessionId);
      if (!consumed.ok) {
        return { ok: false, code: consumed.code, message: consumed.message };
      }

      // Validate the client verifying share and bind relayerKeyId to it.
      let clientVerifyingShareBytes: Uint8Array;
      try {
        clientVerifyingShareBytes = base64UrlDecode(clientVerifyingShareB64u);
      } catch {
        return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u must be valid base64url' };
      }
      if (clientVerifyingShareBytes.length !== 33) {
        return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)' };
      }
      try {
        const point = secp256k1.Point.fromBytes(clientVerifyingShareBytes);
        point.assertValidity();
      } catch {
        return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is not a valid secp256k1 public key' };
      }

      const expectedRelayerKeyIdDigest32 = await sha256BytesUtf8(alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId: tokenRpId,
        clientVerifyingShareB64u,
      }));
      const expectedRelayerKeyId = `secp-${base64UrlEncode(expectedRelayerKeyIdDigest32)}`;
      if (relayerKeyId !== expectedRelayerKeyId) {
        return { ok: false, code: 'unauthorized', message: 'relayerKeyId does not match clientVerifyingShareB64u binding' };
      }

      const signingDigestB64u = base64UrlEncode(signingDigest32);
      const intentDigest32 = await sha256BytesUtf8(alphabetizeStringify({
        version: 'threshold_ecdsa_authorize_intent_v1',
        purpose,
        signingDigestB64u,
      }));

      const ttlMs = 60_000;
      const expiresAtMs = Date.now() + ttlMs;
      const mpcSessionId = this.createThresholdEcdsaMpcSessionId();
      await this.ecdsaSessionStore.putMpcSession(mpcSessionId, {
        expiresAtMs,
        relayerKeyId,
        purpose,
        intentDigestB64u: base64UrlEncode(intentDigest32),
        signingDigestB64u,
        userId,
        rpId: tokenRpId,
        clientVerifyingShareB64u,
        participantIds: [...participantIds],
      }, ttlMs);

      return {
        ok: true,
        mpcSessionId,
        expiresAt: new Date(expiresAtMs).toISOString(),
      };
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Internal error');
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519Session(request: ThresholdEd25519SessionRequest): Promise<ThresholdEd25519SessionResponse> {
    let context: Record<string, unknown> | null = null;
    try {
      const parsedRequest = parseThresholdEd25519SessionRequest(request, this.participantIds2p);
      if (!parsedRequest.ok) return parsedRequest;
      const {
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId,
        rpId,
        sessionId,
        ttlMsRaw,
        remainingUsesRaw,
        policyParticipantIds,
      } = parsedRequest.value;
      context = { nearAccountId, rpId, relayerKeyId, sessionId };

      await this.ensureReady();

      if (!this.verifyWebAuthnAuthenticationLite) {
        return { ok: false, code: 'not_configured', message: 'Lite WebAuthn verification is not configured on this server' };
      }

      const relayerKey = await this.resolveRelayerKeyMaterial({
        relayerKeyId,
        nearAccountId,
        rpId,
        clientVerifyingShareB64u,
      });
      if (!relayerKey.ok) {
        return { ok: false, code: relayerKey.code, message: relayerKey.message };
      }

      const { ttlMs, remainingUses } = this.clampSessionPolicy({ ttlMs: ttlMsRaw, remainingUses: remainingUsesRaw });
      const participantIds = policyParticipantIds || [...this.participantIds2p];
      const normalizedPolicy = {
        version: 'threshold_session_v1',
        nearAccountId,
        rpId,
        relayerKeyId,
        sessionId,
        ...(policyParticipantIds ? { participantIds: policyParticipantIds } : {}),
        ttlMs,
        remainingUses,
      };
      const sessionPolicyDigest32 = await this.computeSessionPolicyDigest32(normalizedPolicy);
      const expectedChallenge = base64UrlEncode(sessionPolicyDigest32);

      const existingSession = await this.authSessionStore.getSession(sessionId);
      if (existingSession) {
        if (existingSession.userId !== nearAccountId) {
          return { ok: false, code: 'unauthorized', message: 'threshold sessionId already exists for a different user' };
        }
        if (existingSession.relayerKeyId !== relayerKeyId) {
          return { ok: false, code: 'unauthorized', message: 'threshold sessionId already exists for a different relayerKeyId' };
        }
        if (existingSession.rpId !== rpId) {
          return { ok: false, code: 'unauthorized', message: 'threshold sessionId already exists for a different rpId' };
        }
        const sameParticipantIds = existingSession.participantIds.length === participantIds.length
          && existingSession.participantIds.every((id, i) => id === participantIds[i]);
        if (!sameParticipantIds) {
          return { ok: false, code: 'unauthorized', message: 'threshold sessionId already exists for a different participant set' };
        }
      }

      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId,
        rpId,
        expectedChallenge,
        webauthn_authentication: request.webauthn_authentication,
      });

      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

      const scope = await ensureRelayerKeyIsActiveAccessKey({
        nearAccountId,
        relayerPublicKey: relayerKey.publicKey,
        viewAccessKeyList: this.viewAccessKeyList,
      });
      if (!scope.ok) {
        return { ok: false, code: scope.code, message: scope.message };
      }

	      if (existingSession) {
	        return {
	          ok: true,
	          sessionId,
	          expiresAtMs: existingSession.expiresAtMs,
	          expiresAt: new Date(existingSession.expiresAtMs).toISOString(),
	          participantIds: existingSession.participantIds,
	        };
	      }

	      const expiresAtMs = Date.now() + ttlMs;
	      await this.putAuthSessionRecord({
	        store: this.authSessionStore,
	        sessionId,
	        record: {
	          expiresAtMs,
	          relayerKeyId,
	          userId: nearAccountId,
	          rpId,
	          participantIds,
	        },
	        ttlMs,
	        remainingUses,
	      });

	      return {
	        ok: true,
	        sessionId,
	        expiresAtMs,
	        expiresAt: new Date(expiresAtMs).toISOString(),
	        participantIds,
	        remainingUses,
	      };
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Internal error');
      this.logger?.error?.('[threshold-ed25519] session mint failed', { message: msg, ...(context || {}) });
      return { ok: false, code: 'internal', message: msg };
    }
  }

  private async ed25519AuthorizeWithSession(input: {
    claims: ThresholdEd25519SessionClaims;
    request: ThresholdEd25519AuthorizeWithSessionRequest;
  }): Promise<ThresholdEd25519AuthorizeResponse> {
    try {
      const claims = input.claims;
      const sessionId = toOptionalTrimmedString(claims?.sessionId);
      if (!sessionId) return { ok: false, code: 'unauthorized', message: 'Missing threshold sessionId' };
      const userId = toOptionalTrimmedString(claims?.sub);
      if (!userId) return { ok: false, code: 'unauthorized', message: 'Missing threshold userId' };

      const tokenRelayerKeyId = toOptionalTrimmedString(claims?.relayerKeyId);
      const tokenRpId = toOptionalTrimmedString(claims?.rpId);
      if (!tokenRelayerKeyId || !tokenRpId) {
        return { ok: false, code: 'unauthorized', message: 'Invalid threshold session token claims' };
      }

      const parsedRequest = parseThresholdEd25519AuthorizeWithSessionRequest(input.request);
      if (!parsedRequest.ok) return parsedRequest;
      const { relayerKeyId, clientVerifyingShareB64u, purpose, signingDigest32, signingPayload } = parsedRequest.value;

      await this.ensureReady();

      // Always validate relayerKeyId from the signed token claims before consuming a use.
      if (relayerKeyId !== tokenRelayerKeyId) {
        return { ok: false, code: 'unauthorized', message: 'relayerKeyId does not match threshold session scope' };
      }

      const thresholdExpiresAtMs = claims.thresholdExpiresAtMs;
      if (Date.now() > thresholdExpiresAtMs) {
        return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
      }

      const participantIds = claims.participantIds;
      for (const id of this.participantIds2p) {
        if (!participantIds.includes(id)) {
          return {
            ok: false,
            code: 'unauthorized',
            message: `threshold session token does not include server signer set (expected to include participantIds=[${this.participantIds2p.join(',')}])`,
          };
        }
      }

      const consumed = await this.authSessionStore.consumeUseCount(sessionId);
      if (!consumed.ok) {
        return { ok: false, code: consumed.code, message: consumed.message };
      }

      const relayerKey = await this.resolveRelayerKeyMaterial({
        relayerKeyId,
        nearAccountId: userId,
        rpId: tokenRpId,
        clientVerifyingShareB64u,
      });
      if (!relayerKey.ok) {
        return { ok: false, code: relayerKey.code, message: relayerKey.message };
      }

      const verifyPayload = await verifyThresholdEd25519AuthorizeSigningPayloadSigningDigestOnly({
        purpose,
        signingPayload,
        signingDigest32,
        userId,
        ensureSignerWasm: this.ensureSignerWasm,
        computeNearTxSigningDigests: threshold_ed25519_compute_near_tx_signing_digests,
        computeDelegateSigningDigest: threshold_ed25519_compute_delegate_signing_digest,
        computeNep413SigningDigest: threshold_ed25519_compute_nep413_signing_digest,
      });
      if (!verifyPayload.ok) {
        return { ok: false, code: verifyPayload.code, message: verifyPayload.message };
      }

      const expectedSigningPublicKey = extractAuthorizeSigningPublicKey(purpose, signingPayload);
      const scope = await ensureRelayerKeyIsActiveAccessKey({
        nearAccountId: userId,
        relayerPublicKey: relayerKey.publicKey,
        ...(expectedSigningPublicKey ? { expectedSigningPublicKey } : {}),
        viewAccessKeyList: this.viewAccessKeyList,
      });
      if (!scope.ok) {
        return { ok: false, code: scope.code, message: scope.message };
      }

      const ttlMs = 60_000;
      const expiresAtMs = Date.now() + ttlMs;
      const mpcSessionId = this.createThresholdEd25519MpcSessionId();
      await this.sessionStore.putMpcSession(mpcSessionId, {
        expiresAtMs,
        relayerKeyId,
        purpose,
        intentDigestB64u: base64UrlEncode(verifyPayload.intentDigest32),
        signingDigestB64u: base64UrlEncode(signingDigest32),
        userId,
        rpId: tokenRpId,
        clientVerifyingShareB64u,
        participantIds: [...participantIds],
      }, ttlMs);

      return {
        ok: true,
        mpcSessionId,
        expiresAt: new Date(expiresAtMs).toISOString(),
      };
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Internal error');
      return { ok: false, code: 'internal', message: msg };
    }
  }

  // Signing round endpoints are exposed via SchemeModule.protocol (see `getSchemeModule`).
}
