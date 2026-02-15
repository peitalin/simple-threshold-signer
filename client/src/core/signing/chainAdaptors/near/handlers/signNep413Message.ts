import {
  WorkerRequestType,
  isSignNep413MessageSuccess,
  isWorkerError,
  type ConfirmationConfig,
  type Nep413SigningResponse,
  type SignerMode,
  type WasmSignNep413MessageRequest,
  type WorkerSuccessResponse,
  getThresholdBehaviorFromSignerMode,
} from '../../../../types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '../../../../types';
import {
  getPrfResultsFromCredential,
  redactCredentialExtensionOutputs,
} from '../../../webauthn/credentials/credentialExtensions';
import { resolveSignerModeForThresholdSigning } from '../../../threshold/session/thresholdEd25519RelayerHealth';
import type {
  LocalNearSkV3Material,
  ThresholdEd25519_2p_V1Material,
} from '../../../../IndexedDBManager/passkeyNearKeysDB';
import {
  clearCachedThresholdEd25519AuthSession,
  getCachedThresholdEd25519AuthSessionJwt,
  makeThresholdEd25519AuthSessionCacheKey,
  mintThresholdEd25519AuthSessionLite,
  putCachedThresholdEd25519AuthSession,
} from '../../../threshold/session/thresholdEd25519AuthSession';
import type { SigningAuthMode } from '../../../secureConfirm/confirmTxFlow/types';
import {
  buildThresholdSessionPolicy,
  isThresholdSessionAuthUnavailableError,
  isThresholdSignerMissingKeyError,
} from '../../../threshold/session/thresholdSessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '../../../../../../../shared/src/threshold/participants';
import {
  getLastLoggedInDeviceNumber,
  parseDeviceNumber,
} from '../../../webauthn/device/getDeviceNumber';
function generateSessionId(): string {
  return `sess-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}
import type { SigningRuntimeDeps } from '../../types';
import { toAccountId } from '../../../../types/accountIds';
import { deriveThresholdEd25519ClientVerifyingShare } from '../../../threshold/workflows/deriveThresholdEd25519ClientVerifyingShare';
import { executeSignerWorkerOperation } from '../../../workers/operations/executeSignerWorkerOperation';
import {
  assertRuntimeSigningLocalKeyMaterial,
  isRuntimeSigningLocalKeyMaterial,
} from './localKeyUsage';

const DUMMY_WRAP_KEY_SALT_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

/**
 * Sign a NEP-413 message using the user's passkey-derived private key
 *
 * @param payload - NEP-413 signing parameters including message, recipient, nonce, and state
 * @returns Promise resolving to signing result with account ID, public key, and signature
 */
export async function signNep413Message({
  ctx,
  payload,
}: {
  ctx: SigningRuntimeDeps;
  payload: {
    message: string;
    recipient: string;
    nonce: string;
    state: string | null;
    accountId: string;
    signerMode: SignerMode;
    deviceNumber?: number;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    signingSessionTtlMs?: number;
    signingSessionRemainingUses?: number;
    sessionId?: string;
    contractId?: string;
    nearRpcUrl?: string;
  };
}): Promise<{
  success: boolean;
  accountId: string;
  publicKey: string;
  signature: string;
  state?: string;
  error?: string;
}> {
  try {
    const sessionId = payload.sessionId ?? generateSessionId();
    const relayerUrl = ctx.relayerUrl;
    const nearAccountId = payload.accountId;
    const thresholdBehavior = getThresholdBehaviorFromSignerMode(payload.signerMode);

    const parsedDeviceNumber = parseDeviceNumber(payload.deviceNumber, { min: 1 });
    if (payload.deviceNumber !== undefined && parsedDeviceNumber === null) {
      throw new Error(`Invalid deviceNumber for NEP-413 signing: ${payload.deviceNumber}`);
    }
    const resolvedDeviceNumber =
      parsedDeviceNumber ??
      (await getLastLoggedInDeviceNumber(nearAccountId, ctx.indexedDB.clientDB));
    const nearAccount = toAccountId(nearAccountId);
    const thresholdKeyMaterial = await ctx.indexedDB.getNearThresholdKeyMaterialV2First(
      nearAccount,
      resolvedDeviceNumber,
    );

    const resolvedSignerMode = await resolveSignerModeForThresholdSigning({
      nearAccountId,
      signerMode: payload.signerMode,
      relayerUrl,
      hasThresholdKeyMaterial: !!thresholdKeyMaterial,
    });

    const localKeyMaterialCandidate =
      resolvedSignerMode === 'local-signer' || thresholdBehavior === 'fallback'
        ? await ctx.indexedDB.getNearLocalKeyMaterialV2First(nearAccount, resolvedDeviceNumber)
        : null;
    if (localKeyMaterialCandidate && !isRuntimeSigningLocalKeyMaterial(localKeyMaterialCandidate)) {
      if (resolvedSignerMode === 'local-signer' && !thresholdKeyMaterial) {
        assertRuntimeSigningLocalKeyMaterial({
          nearAccountId: String(nearAccountId),
          localKeyMaterial: localKeyMaterialCandidate,
        });
      }
      console.warn(
        `[WebAuthnManager] export-only local key material is excluded from runtime signing for account: ${nearAccountId}`,
      );
    }
    const localKeyMaterial = isRuntimeSigningLocalKeyMaterial(localKeyMaterialCandidate)
      ? localKeyMaterialCandidate
      : null;
    const localWrapKeySalt = String(localKeyMaterial?.wrapKeySalt || '').trim();
    const thresholdWrapKeySalt =
      String(thresholdKeyMaterial?.wrapKeySalt || '').trim() || DUMMY_WRAP_KEY_SALT_B64U;

    if (resolvedSignerMode === 'local-signer') {
      if (!localKeyMaterial) {
        throw new Error(`No local key material found for account: ${nearAccountId}`);
      }
      if (!localWrapKeySalt) {
        throw new Error(`Missing wrapKeySalt for account: ${nearAccountId}`);
      }
    }

    const secureConfirmWorkerManager = ctx.secureConfirmWorkerManager;
    if (!secureConfirmWorkerManager) {
      throw new Error('SecureConfirmWorkerManager not available for NEP-413 signing');
    }

    const signingContext = validateAndPrepareNep413SigningContext({
      nearAccountId,
      resolvedSignerMode,
      relayerUrl,
      rpId: ctx.touchIdPrompt.getRpId(),
      localKeyMaterial,
      thresholdKeyMaterial,
    });

    // Initialize nonce manager for a better SecureConfirm context (block height + access key lookup).
    // NEP-413 signing itself doesn't require nonces, but SecureConfirm uses Near context for UI.
    ctx.nonceManager.initializeUser(toAccountId(nearAccountId), signingContext.nearPublicKey);

    const usesNeeded = 1;
    const desiredTtlMs =
      typeof payload.signingSessionTtlMs === 'number' &&
      Number.isFinite(payload.signingSessionTtlMs) &&
      payload.signingSessionTtlMs > 0
        ? Math.floor(payload.signingSessionTtlMs)
        : undefined;
    const desiredRemainingUses =
      typeof payload.signingSessionRemainingUses === 'number' &&
      Number.isFinite(payload.signingSessionRemainingUses) &&
      payload.signingSessionRemainingUses > 0
        ? Math.floor(payload.signingSessionRemainingUses)
        : undefined;
    let thresholdSessionPlan: Awaited<ReturnType<typeof buildThresholdSessionPolicy>> | null = null;
    let signingAuthMode: SigningAuthMode | undefined;
    if (signingContext.threshold) {
      const hasJwt = !!signingContext.threshold.thresholdSessionJwt;
      let warmOk = false;
      if (hasJwt) {
        const peek = await secureConfirmWorkerManager.peekPrfFirstForThresholdSession({
          sessionId,
        });
        warmOk = peek.ok && peek.remainingUses >= usesNeeded;
      }
      signingAuthMode = warmOk ? 'warmSession' : 'webauthn';
      if (!warmOk) {
        const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
        thresholdSessionPlan = await buildThresholdSessionPolicy({
          nearAccountId,
          rpId,
          relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
          participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map(
            (p) => p.id,
          ),
          ...(desiredTtlMs !== undefined ? { ttlMs: desiredTtlMs } : {}),
          remainingUses: Math.max(usesNeeded, desiredRemainingUses ?? usesNeeded),
        });
      }
    }

    const confirmation = await secureConfirmWorkerManager.confirmAndPrepareSigningSession({
      ctx,
      sessionId,
      kind: 'nep413',
      ...(signingAuthMode ? { signingAuthMode } : {}),
      ...(thresholdSessionPlan
        ? { sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32 }
        : {}),
      nearAccountId,
      message: payload.message,
      recipient: payload.recipient,
      title: payload.title,
      body: payload.body,
      confirmationConfigOverride: payload.confirmationConfigOverride,
      contractId: payload.contractId,
      nearRpcUrl: payload.nearRpcUrl,
    });

    let credentialWithPrf: WebAuthnAuthenticationCredential | undefined =
      confirmation.credential as WebAuthnAuthenticationCredential | undefined;
    let credentialForRelayJson = credentialWithPrf
      ? JSON.stringify(redactCredentialExtensionOutputs(credentialWithPrf))
      : undefined;

    let prfFirstB64u: string | undefined;

    if (signingContext.threshold && signingAuthMode === 'warmSession') {
      const delivered = await secureConfirmWorkerManager.dispensePrfFirstForThresholdSession({
        sessionId,
        uses: usesNeeded,
      });
      if (delivered.ok) {
        prfFirstB64u = delivered.prfFirstB64u;
      } else {
        await secureConfirmWorkerManager
          .clearPrfFirstForThresholdSession({ sessionId })
          .catch(() => {});
        signingAuthMode = 'webauthn';

        const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
        thresholdSessionPlan = await buildThresholdSessionPolicy({
          nearAccountId,
          rpId,
          relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
          participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map(
            (p) => p.id,
          ),
          ...(desiredTtlMs !== undefined ? { ttlMs: desiredTtlMs } : {}),
          remainingUses: Math.max(usesNeeded, desiredRemainingUses ?? usesNeeded),
        });

        const refreshed = await secureConfirmWorkerManager.confirmAndPrepareSigningSession({
          ctx,
          sessionId,
          kind: 'nep413',
          signingAuthMode: 'webauthn',
          sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
          nearAccountId,
          message: payload.message,
          recipient: payload.recipient,
          title: payload.title,
          body: payload.body,
          confirmationConfigOverride: payload.confirmationConfigOverride,
          contractId: payload.contractId,
          nearRpcUrl: payload.nearRpcUrl,
        });

        credentialWithPrf = refreshed.credential as WebAuthnAuthenticationCredential | undefined;
        credentialForRelayJson = credentialWithPrf
          ? JSON.stringify(redactCredentialExtensionOutputs(credentialWithPrf))
          : undefined;
        prfFirstB64u = getPrfResultsFromCredential(credentialWithPrf).first;
        if (!prfFirstB64u) {
          throw new Error(
            'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
          );
        }
      }
    } else {
      prfFirstB64u = getPrfResultsFromCredential(credentialWithPrf).first;
      if (!prfFirstB64u) {
        throw new Error(
          'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
        );
      }
    }

    if (!prfFirstB64u) {
      throw new Error('Missing PRF.first output for signing');
    }

    if (signingContext.threshold && signingAuthMode !== 'warmSession') {
      if (!credentialWithPrf) {
        throw new Error('Missing WebAuthn credential for threshold session mint');
      }
      if (!thresholdSessionPlan) {
        throw new Error('Missing threshold session policy for threshold session mint');
      }

      const derived = await deriveThresholdEd25519ClientVerifyingShare({
        ctx,
        sessionId,
        nearAccountId,
        prfFirstB64u,
        wrapKeySalt: thresholdWrapKeySalt,
      });
      if (!derived.success) {
        throw new Error(derived.error || 'Failed to derive client verifying share');
      }

      const minted = await mintThresholdEd25519AuthSessionLite({
        relayerUrl: signingContext.threshold.relayerUrl,
        sessionKind: 'jwt',
        relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
        clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
        sessionPolicy: thresholdSessionPlan.policy,
        webauthnAuthentication: credentialWithPrf,
      });
      if (!minted.ok || !minted.jwt) {
        throw new Error(minted.message || 'Failed to mint threshold session');
      }

      const expiresAtMs = minted.expiresAtMs ?? Date.now() + thresholdSessionPlan.policy.ttlMs;
      const remainingUses = minted.remainingUses ?? thresholdSessionPlan.policy.remainingUses;

      if (!prfFirstB64u) {
        throw new Error('Missing PRF.first output for threshold session cache');
      }
      await secureConfirmWorkerManager
        .putPrfFirstForThresholdSession({
          sessionId,
          prfFirstB64u,
          expiresAtMs,
          remainingUses,
        })
        .catch(() => {});

      putCachedThresholdEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey, {
        sessionKind: 'jwt',
        policy: thresholdSessionPlan.policy,
        policyJson: thresholdSessionPlan.policyJson,
        sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
        jwt: minted.jwt,
        expiresAtMs,
      });

      signingContext.threshold.thresholdSessionJwt = minted.jwt;
    }

    if (signingContext.threshold && !signingContext.threshold.thresholdSessionJwt) {
      throw new Error('Missing thresholdSessionJwt for threshold NEP-413 signing');
    }

    const requestPayload: Omit<WasmSignNep413MessageRequest, 'sessionId'> = {
      signerMode: signingContext.resolvedSignerMode,
      message: payload.message,
      recipient: payload.recipient,
      nonce: payload.nonce,
      state: payload.state || undefined,
      accountId: nearAccountId,
      nearPublicKey: signingContext.nearPublicKey,
      prfFirstB64u,
      wrapKeySalt: signingContext.threshold ? thresholdWrapKeySalt : localWrapKeySalt,
      decryption: signingContext.decryption,
      threshold: signingContext.threshold
        ? {
            relayerUrl: signingContext.threshold.relayerUrl,
            relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
            clientParticipantId: signingContext.threshold.thresholdKeyMaterial.participants.find(
              (p) => p.role === 'client',
            )?.id,
            relayerParticipantId: signingContext.threshold.thresholdKeyMaterial.participants.find(
              (p) => p.role === 'relayer',
            )?.id,
            participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map(
              (p) => p.id,
            ),
            thresholdSessionKind: 'jwt' as const,
            thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
          }
        : undefined,
      credential: credentialForRelayJson,
    };

    if (!signingContext.threshold) {
      const response = await executeSignerWorkerOperation({
        ctx,
        kind: 'nearSigner',
        request: {
          sessionId,
          type: WorkerRequestType.SignNep413Message,
          payload: requestPayload,
        },
      });
      const okResponse = requireOkSignNep413MessageResponse(response);

      return {
        success: true,
        accountId: okResponse.payload.accountId,
        publicKey: okResponse.payload.publicKey,
        signature: okResponse.payload.signature,
        state: okResponse.payload.state || undefined,
      };
    }

    let okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignNep413Message> | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await executeSignerWorkerOperation({
          ctx,
          kind: 'nearSigner',
          request: {
            sessionId,
            type: WorkerRequestType.SignNep413Message,
            payload: requestPayload,
          },
        });
        okResponse = requireOkSignNep413MessageResponse(response);
        break;
      } catch (e: unknown) {
        const err = e instanceof Error ? e : new Error(String(e));

        if (isThresholdSignerMissingKeyError(err)) {
          const msg =
            '[WebAuthnManager] threshold-signer requested but the relayer is missing the signing share; local fallback is disabled';
          clearCachedThresholdEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
          signingContext.threshold.thresholdSessionJwt = undefined;
          throw new Error(msg);
        }

        if (attempt === 0 && isThresholdSessionAuthUnavailableError(err)) {
          clearCachedThresholdEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
          await secureConfirmWorkerManager
            .clearPrfFirstForThresholdSession({ sessionId })
            .catch(() => {});
          signingContext.threshold.thresholdSessionJwt = undefined;
          requestPayload.threshold!.thresholdSessionJwt = undefined;

          const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
          thresholdSessionPlan = await buildThresholdSessionPolicy({
            nearAccountId,
            rpId,
            relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
            participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map(
              (p) => p.id,
            ),
            ...(desiredTtlMs !== undefined ? { ttlMs: desiredTtlMs } : {}),
            remainingUses: Math.max(usesNeeded, desiredRemainingUses ?? usesNeeded),
          });

          const refreshed = await secureConfirmWorkerManager.confirmAndPrepareSigningSession({
            ctx,
            sessionId,
            kind: 'nep413',
            signingAuthMode: 'webauthn',
            sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
            nearAccountId,
            message: payload.message,
            recipient: payload.recipient,
            title: payload.title,
            body: payload.body,
            confirmationConfigOverride: payload.confirmationConfigOverride,
            contractId: payload.contractId,
            nearRpcUrl: payload.nearRpcUrl,
          });

          credentialWithPrf = refreshed.credential as WebAuthnAuthenticationCredential | undefined;
          credentialForRelayJson = credentialWithPrf
            ? JSON.stringify(redactCredentialExtensionOutputs(credentialWithPrf))
            : undefined;

          const prfFirst = getPrfResultsFromCredential(credentialWithPrf).first;
          if (!prfFirst) {
            throw new Error(
              'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
            );
          }

          const derived = await deriveThresholdEd25519ClientVerifyingShare({
            ctx,
            sessionId,
            nearAccountId,
            prfFirstB64u: prfFirst,
            wrapKeySalt: thresholdWrapKeySalt,
          });
          if (!derived.success) {
            throw new Error(derived.error || 'Failed to derive client verifying share');
          }

          const minted = await mintThresholdEd25519AuthSessionLite({
            relayerUrl: signingContext.threshold.relayerUrl,
            sessionKind: 'jwt',
            relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
            clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
            sessionPolicy: thresholdSessionPlan.policy,
            webauthnAuthentication: credentialWithPrf!,
          });
          if (!minted.ok || !minted.jwt) {
            throw new Error(minted.message || 'Failed to mint threshold session');
          }

          const expiresAtMs = minted.expiresAtMs ?? Date.now() + thresholdSessionPlan.policy.ttlMs;
          const remainingUses = minted.remainingUses ?? thresholdSessionPlan.policy.remainingUses;

          await secureConfirmWorkerManager
            .putPrfFirstForThresholdSession({
              sessionId,
              prfFirstB64u: prfFirst,
              expiresAtMs,
              remainingUses,
            })
            .catch(() => {});

          putCachedThresholdEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey, {
            sessionKind: 'jwt',
            policy: thresholdSessionPlan.policy,
            policyJson: thresholdSessionPlan.policyJson,
            sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
            jwt: minted.jwt,
            expiresAtMs,
          });

          signingContext.threshold.thresholdSessionJwt = minted.jwt;
          requestPayload.threshold!.thresholdSessionJwt = minted.jwt;
          requestPayload.credential = credentialForRelayJson;
          continue;
        }

        throw err;
      }
    }

    if (!okResponse) {
      throw new Error('No NEP-413 signing response received');
    }

    return {
      success: true,
      accountId: okResponse.payload.accountId,
      publicKey: okResponse.payload.publicKey,
      signature: okResponse.payload.signature,
      state: okResponse.payload.state || undefined,
    };
  } catch (error: unknown) {
    console.error('SignerWorkerManager: NEP-413 signing error:', error);
    return {
      success: false,
      accountId: '',
      publicKey: '',
      signature: '',
      error:
        error && typeof (error as { message?: unknown }).message === 'string'
          ? (error as { message: string }).message
          : 'Unknown error',
    };
  }
}

type ThresholdNep413SigningContext = {
  resolvedSignerMode: 'threshold-signer';
  nearPublicKey: string;
  decryption: { encryptedPrivateKeyData: string; encryptedPrivateKeyChacha20NonceB64u: string };
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519_2p_V1Material;
    thresholdSessionCacheKey: string;
    thresholdSessionJwt: string | undefined;
  };
};

type LocalNep413SigningContext = {
  resolvedSignerMode: 'local-signer';
  nearPublicKey: string;
  decryption: { encryptedPrivateKeyData: string; encryptedPrivateKeyChacha20NonceB64u: string };
  threshold: null;
};

type Nep413SigningContext = ThresholdNep413SigningContext | LocalNep413SigningContext;

function validateAndPrepareNep413SigningContext(args: {
  nearAccountId: string;
  resolvedSignerMode: SignerMode['mode'];
  relayerUrl: string;
  rpId: string | null;
  localKeyMaterial: LocalNearSkV3Material | null;
  thresholdKeyMaterial: ThresholdEd25519_2p_V1Material | null;
}): Nep413SigningContext {
  if (args.resolvedSignerMode !== 'threshold-signer') {
    if (!args.localKeyMaterial) {
      throw new Error(`No local key material found for account: ${args.nearAccountId}`);
    }
    const localPublicKey = String(args.localKeyMaterial.publicKey || '').trim();
    if (!localPublicKey) {
      throw new Error(`Missing local signing public key for ${args.nearAccountId}`);
    }
    return {
      resolvedSignerMode: 'local-signer',
      nearPublicKey: localPublicKey,
      decryption: {
        encryptedPrivateKeyData: args.localKeyMaterial.encryptedSk,
        encryptedPrivateKeyChacha20NonceB64u: args.localKeyMaterial.chacha20NonceB64u,
      },
      threshold: null,
    };
  }

  const thresholdKeyMaterial = args.thresholdKeyMaterial;
  if (!thresholdKeyMaterial) {
    throw new Error(`Missing threshold key material for ${args.nearAccountId}`);
  }

  const thresholdPublicKey = String(thresholdKeyMaterial.publicKey || '').trim();
  if (!thresholdPublicKey) {
    throw new Error(`Missing threshold signing public key for ${args.nearAccountId}`);
  }

  const relayerUrl = String(args.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayerUrl (required for threshold-signer)');
  }

  const rpId = String(args.rpId || '').trim();
  if (!rpId) {
    throw new Error('Missing rpId for threshold signing');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(
    thresholdKeyMaterial.participants.map((p) => p.id),
  );
  if (!participantIds || participantIds.length < 2) {
    throw new Error(
      `Invalid threshold signing participantIds (expected >=2 participants, got [${(participantIds || []).join(',')}])`,
    );
  }

  const thresholdSessionCacheKey = makeThresholdEd25519AuthSessionCacheKey({
    nearAccountId: args.nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId: thresholdKeyMaterial.relayerKeyId,
    participantIds,
  });

  return {
    resolvedSignerMode: 'threshold-signer',
    nearPublicKey: thresholdPublicKey,
    decryption: {
      encryptedPrivateKeyData: '',
      encryptedPrivateKeyChacha20NonceB64u: '',
    },
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
      thresholdSessionCacheKey,
      thresholdSessionJwt: getCachedThresholdEd25519AuthSessionJwt(thresholdSessionCacheKey),
    },
  };
}

function requireOkSignNep413MessageResponse(
  response: Nep413SigningResponse,
): WorkerSuccessResponse<typeof WorkerRequestType.SignNep413Message> {
  if (!isSignNep413MessageSuccess(response)) {
    if (isWorkerError(response)) {
      throw new Error(response.payload.error || 'NEP-413 signing failed');
    }
    throw new Error('NEP-413 signing failed');
  }
  return response;
}
