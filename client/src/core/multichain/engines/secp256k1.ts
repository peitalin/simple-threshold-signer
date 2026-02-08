import type { KeyRef, SignRequest, SignerEngine, SignatureBytes } from '../types';
import { signSecp256k1RecoverableWasm } from '../evm/ethSignerWasm';
import { authorizeThresholdEcdsaWithSession } from '../../threshold/thresholdEcdsaAuthorize';
import { deriveThresholdSecp256k1ClientShare } from '../../threshold/deriveThresholdSecp256k1ClientShare';
import {
  getCachedThresholdEcdsaAuthSession,
  getCachedThresholdEcdsaAuthSessionJwt,
  makeThresholdEcdsaAuthSessionCacheKey,
} from '../../threshold/thresholdEcdsaAuthSession';
import { signThresholdEcdsaDigestWithPool } from '../walletOrigin/thresholdEcdsaCoordinator';

type ThresholdEcdsaSessionKind = 'jwt' | 'cookie';

export type ThresholdEcdsaPrfFirstDispenseFn = (args: {
  sessionId: string;
  uses?: number;
}) => Promise<
  | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string }
>;

export class Secp256k1Engine implements SignerEngine {
  readonly algorithm = 'secp256k1' as const;

  private readonly getRpId?: () => string | null;
  private readonly dispenseThresholdEcdsaPrfFirstForSession?: ThresholdEcdsaPrfFirstDispenseFn;

  constructor(opts?: {
    getRpId?: () => string | null;
    dispenseThresholdEcdsaPrfFirstForSession?: ThresholdEcdsaPrfFirstDispenseFn;
  }) {
    this.getRpId = opts?.getRpId;
    this.dispenseThresholdEcdsaPrfFirstForSession = opts?.dispenseThresholdEcdsaPrfFirstForSession;
  }

  async sign(req: SignRequest, keyRef: KeyRef): Promise<SignatureBytes> {
    if (req.kind !== 'digest' || req.algorithm !== 'secp256k1') {
      throw new Error('[Secp256k1Engine] unsupported sign request');
    }
    if (req.digest32.length !== 32) {
      throw new Error('[Secp256k1Engine] digest32 must be 32 bytes');
    }

    if (keyRef.type === 'local-secp256k1') {
      if (keyRef.privateKey.length !== 32) {
        throw new Error('[Secp256k1Engine] privateKey must be 32 bytes');
      }
      return await signSecp256k1RecoverableWasm({
        digest32: req.digest32,
        privateKey32: keyRef.privateKey,
      });
    }

    if (keyRef.type !== 'threshold-ecdsa-secp256k1') {
      throw new Error('[Secp256k1Engine] keyRef must be local-secp256k1 or threshold-ecdsa-secp256k1');
    }

    const rpId = this.getRpId?.() || null;
    const cacheKey = rpId
      ? makeThresholdEcdsaAuthSessionCacheKey({
          userId: keyRef.userId,
          rpId,
          relayerUrl: keyRef.relayerUrl,
          relayerKeyId: keyRef.relayerKeyId,
          participantIds: keyRef.participantIds,
        })
      : null;
    const cachedThresholdSession = cacheKey ? getCachedThresholdEcdsaAuthSession(cacheKey) : null;

    const sessionKind: ThresholdEcdsaSessionKind = keyRef.thresholdSessionKind || 'jwt';
    const thresholdSessionJwt = sessionKind === 'jwt'
      ? (
          keyRef.thresholdSessionJwt
          || (cacheKey ? getCachedThresholdEcdsaAuthSessionJwt(cacheKey) : undefined)
        )
      : undefined;

    if (sessionKind === 'jwt' && !thresholdSessionJwt) {
      throw new Error('[multichain] No cached threshold-ecdsa session token; call connectThresholdEcdsaSessionLite first');
    }

    const purpose = String(req.label || 'secp256k1');
    const authorized = await authorizeThresholdEcdsaWithSession({
      relayerUrl: keyRef.relayerUrl,
      relayerKeyId: keyRef.relayerKeyId,
      clientVerifyingShareB64u: keyRef.clientVerifyingShareB64u,
      purpose,
      signingDigest32: req.digest32,
      sessionKind,
      ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    });
    if (!authorized.ok || !authorized.mpcSessionId) {
      throw new Error(authorized.message || authorized.code || '[multichain] threshold-ecdsa authorize failed');
    }
    keyRef.mpcSessionId = authorized.mpcSessionId;

    const thresholdSessionId = String(
      keyRef.thresholdSessionId
      || cachedThresholdSession?.policy?.sessionId
      || ''
    ).trim();
    if (!thresholdSessionId) {
      throw new Error('[multichain] Missing threshold-ecdsa sessionId; reconnect session via connectThresholdEcdsaSessionLite');
    }
    if (!this.dispenseThresholdEcdsaPrfFirstForSession) {
      throw new Error('[multichain] Missing PRF.first dispenser for threshold-ecdsa signing');
    }

    const dispensed = await this.dispenseThresholdEcdsaPrfFirstForSession({
      sessionId: thresholdSessionId,
      uses: 1,
    });
    if (!dispensed.ok) {
      throw new Error(dispensed.message || dispensed.code || '[multichain] failed to load PRF.first for threshold-ecdsa signing');
    }

    const derived = deriveThresholdSecp256k1ClientShare({
      prfFirstB64u: dispensed.prfFirstB64u,
      userId: keyRef.userId,
    });
    if (derived.clientVerifyingShareB64u !== keyRef.clientVerifyingShareB64u) {
      throw new Error('[multichain] Derived client share does not match keyRef.clientVerifyingShareB64u');
    }

    const signed = await signThresholdEcdsaDigestWithPool({
      relayerUrl: keyRef.relayerUrl,
      relayerKeyId: keyRef.relayerKeyId,
      clientVerifyingShareB64u: keyRef.clientVerifyingShareB64u,
      mpcSessionId: authorized.mpcSessionId,
      signingDigest32: req.digest32,
      clientSigningShare32: derived.clientSigningShare32,
      participantIds: keyRef.participantIds || cachedThresholdSession?.policy?.participantIds,
      groupPublicKeyB64u: keyRef.groupPublicKeyB64u,
      relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
      sessionKind,
      ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    });
    if (!signed.ok) {
      throw new Error(signed.message || signed.code || '[multichain] threshold-ecdsa signing failed');
    }

    return signed.signature65;
  }
}

