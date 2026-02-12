import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '../../../../config/defaultConfigs';
import { AccountId, toAccountId } from '../../../../types/accountIds';
import { toActionArgsWasm, validateActionArgsWasm } from '../../../../types/actions';
import { DelegateActionInput } from '../../../../types/delegate';
import { type onProgressEvents } from '../../../../types/sdkSentEvents';
import {
  ConfirmationConfig,
  RpcCallPayload,
  type SignerMode,
  WorkerRequestType,
  type DelegateSignResponse,
  type WasmSignDelegateActionRequest,
  isWorkerError,
  isSignDelegateActionSuccess,
  type WorkerSuccessResponse,
  WasmSignedDelegate,
  getThresholdBehaviorFromSignerMode,
} from '../../../../types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '../../../../types';
import {
  getPrfResultsFromCredential,
  redactCredentialExtensionOutputs,
} from '../../../webauthn/credentials/credentialExtensions';
import {
  isRelayerThresholdEd25519Configured,
  resolveSignerModeForThresholdSigning,
} from '../../../threshold/session/thresholdEd25519RelayerHealth';
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
import type { SigningRuntimeDeps } from '../../types';
import {
  getLastLoggedInDeviceNumber,
  parseDeviceNumber,
} from '../../../webauthn/device/getDeviceNumber';
function generateSessionId(): string {
  return `sess-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}
import {
  ensureEd25519Prefix,
  toPublicKeyString,
} from '../../../workers/signerWorkerManager/internal/validation';
import { deriveThresholdEd25519ClientVerifyingShare } from '../../../threshold/workflows/deriveThresholdEd25519ClientVerifyingShare';
import { executeSignerWorkerOperation } from '../../handlers/executeSignerWorkerOperation';

const DUMMY_WRAP_KEY_SALT_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export async function signDelegateAction({
  ctx,
  delegate,
  rpcCall,
  signerMode,
  onEvent,
  confirmationConfigOverride,
  title,
  body,
  signingSessionTtlMs,
  signingSessionRemainingUses,
  sessionId: providedSessionId,
  deviceNumber,
}: {
  ctx: SigningRuntimeDeps;
  delegate: DelegateActionInput;
  rpcCall: RpcCallPayload;
  signerMode: SignerMode;
  onEvent?: (update: onProgressEvents) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signingSessionTtlMs?: number;
  signingSessionRemainingUses?: number;
  sessionId?: string;
  deviceNumber?: number;
}): Promise<{
  signedDelegate: WasmSignedDelegate;
  hash: string;
  nearAccountId: AccountId;
  logs?: string[];
}> {
  const sessionId = providedSessionId ?? generateSessionId();
  const nearAccountId = toAccountId(rpcCall.nearAccountId || delegate.senderId);
  const relayerUrl = ctx.relayerUrl;

  const resolvedRpcCall = {
    contractId: rpcCall.contractId || PASSKEY_MANAGER_DEFAULT_CONFIGS.contractId,
    nearRpcUrl: rpcCall.nearRpcUrl || (PASSKEY_MANAGER_DEFAULT_CONFIGS.nearRpcUrl.split(',')[0] || PASSKEY_MANAGER_DEFAULT_CONFIGS.nearRpcUrl),
    nearAccountId,
  } as RpcCallPayload;

  const actionsWasm = delegate.actions.map(toActionArgsWasm);
  actionsWasm.forEach((action, actionIndex) => {
    try {
      validateActionArgsWasm(action);
    } catch (error) {
      throw new Error(
        `Delegate action ${actionIndex} validation failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  });

  const parsedDeviceNumber = parseDeviceNumber(deviceNumber, { min: 1 });
  if (deviceNumber !== undefined && parsedDeviceNumber === null) {
    throw new Error(`Invalid deviceNumber for delegate signing: ${deviceNumber}`);
  }
  const resolvedDeviceNumber = parsedDeviceNumber
    ?? await getLastLoggedInDeviceNumber(nearAccountId, ctx.indexedDB.clientDB);
  const thresholdKeyMaterial = await ctx.indexedDB.getNearThresholdKeyMaterialV2First(
    nearAccountId,
    resolvedDeviceNumber,
  );

  const warnings: string[] = [];
  const thresholdBehavior = getThresholdBehaviorFromSignerMode(signerMode);
  const secureConfirmWorkerManager = ctx.secureConfirmWorkerManager;
  if (!secureConfirmWorkerManager) {
    throw new Error('SecureConfirmWorkerManager not available for delegate signing');
  }

  let resolvedSignerMode = await resolveSignerModeForThresholdSigning({
    nearAccountId,
    signerMode,
    relayerUrl,
    hasThresholdKeyMaterial: !!thresholdKeyMaterial,
    warnings,
  });

  const localKeyMaterial = (resolvedSignerMode === 'local-signer' || thresholdBehavior === 'fallback')
    ? await ctx.indexedDB.getNearLocalKeyMaterialV2First(
      nearAccountId,
      resolvedDeviceNumber,
    )
    : null;
  const localWrapKeySalt = String(localKeyMaterial?.wrapKeySalt || '').trim();
  const thresholdWrapKeySalt = String(thresholdKeyMaterial?.wrapKeySalt || '').trim() || DUMMY_WRAP_KEY_SALT_B64U;

  // If the caller defaulted to local-signer but the account is threshold-only, prefer threshold-signer.
  // This avoids hard failures for newly-registered threshold accounts where no local vault key is stored.
  if (resolvedSignerMode === 'local-signer' && !localKeyMaterial && !!thresholdKeyMaterial) {
    const configured = await isRelayerThresholdEd25519Configured(relayerUrl).catch(() => false);
    if (!configured) {
      throw new Error(
        '[WebAuthnManager] local-signer requested but no local key material found and the relayer is not configured for threshold signing'
      );
    }
    const msg =
      `[WebAuthnManager] local-signer requested but no local key material found for account: ${nearAccountId}; using threshold-signer`;
    // eslint-disable-next-line no-console
    console.warn(msg);
    warnings.push(msg);
    resolvedSignerMode = 'threshold-signer';
  }

  if (resolvedSignerMode === 'local-signer') {
    if (!localKeyMaterial) {
      throw new Error(`No local key material found for account: ${nearAccountId}`);
    }
    if (!localWrapKeySalt) {
      throw new Error(`Missing wrapKeySalt for account: ${nearAccountId}`);
    }
  }

  const canFallbackToLocal = thresholdBehavior === 'fallback' && !!localKeyMaterial && !!localWrapKeySalt;

  const signingContext = validateAndPrepareDelegateSigningContext({
    nearAccountId,
    resolvedSignerMode,
    relayerUrl,
    rpId: ctx.touchIdPrompt.getRpId(),
    localKeyMaterial,
    thresholdKeyMaterial,
    providedDelegatePublicKey: delegate.publicKey,
    warnings,
  });

  // Ensure nonce/block context is fetched for the same access key that will sign.
  // Threshold signing MUST use the threshold/group public key (relayer access key) for:
  // - correct nonce reservation
  // - relayer scope checks (/authorize expects signingPayload.delegate.publicKey == relayer key)
  ctx.nonceManager.initializeUser(toAccountId(nearAccountId), signingContext.signingNearPublicKeyStr);

  const usesNeeded = 1;
  const desiredTtlMs =
    typeof signingSessionTtlMs === 'number' && Number.isFinite(signingSessionTtlMs) && signingSessionTtlMs > 0
      ? Math.floor(signingSessionTtlMs)
      : undefined;
  const desiredRemainingUses =
    typeof signingSessionRemainingUses === 'number' && Number.isFinite(signingSessionRemainingUses) && signingSessionRemainingUses > 0
      ? Math.floor(signingSessionRemainingUses)
      : undefined;
  let thresholdSessionPlan:
    | Awaited<ReturnType<typeof buildThresholdSessionPolicy>>
    | null = null;
  let signingAuthMode: SigningAuthMode | undefined;
  if (signingContext.threshold) {
    const hasJwt = !!signingContext.threshold.thresholdSessionJwt;
    let warmOk = false;
    if (hasJwt) {
      const peek = await secureConfirmWorkerManager.peekPrfFirstForThresholdSession({ sessionId });
      warmOk = peek.ok && peek.remainingUses >= usesNeeded;
    }
    signingAuthMode = warmOk ? 'warmSession' : 'webauthn';
    if (!warmOk) {
      const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
      thresholdSessionPlan = await buildThresholdSessionPolicy({
        nearAccountId,
        rpId,
        relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
        participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map((p) => p.id),
        ...(desiredTtlMs !== undefined ? { ttlMs: desiredTtlMs } : {}),
        remainingUses: Math.max(usesNeeded, desiredRemainingUses ?? usesNeeded),
      });
    }
  }

  const confirmation = await secureConfirmWorkerManager.confirmAndPrepareSigningSession({
    ctx,
    sessionId,
    kind: 'delegate',
    ...(signingAuthMode ? { signingAuthMode } : {}),
    ...(thresholdSessionPlan ? { sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32 } : {}),
    nearAccountId,
    delegate: {
      senderId: delegate.senderId || nearAccountId,
      receiverId: delegate.receiverId,
      actions: actionsWasm,
      nonce: delegate.nonce,
      maxBlockHeight: delegate.maxBlockHeight,
    },
    rpcCall: resolvedRpcCall,
    confirmationConfigOverride,
    title,
    body,
  });

  let intentDigest = confirmation.intentDigest;
  let transactionContext = confirmation.transactionContext;

  let credentialWithPrf: WebAuthnAuthenticationCredential | undefined = confirmation.credential as
    | WebAuthnAuthenticationCredential
    | undefined;

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
      await secureConfirmWorkerManager.clearPrfFirstForThresholdSession({ sessionId }).catch(() => { });
      signingAuthMode = 'webauthn';

      const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
      thresholdSessionPlan = await buildThresholdSessionPolicy({
        nearAccountId,
        rpId,
        relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
        participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map((p) => p.id),
        ...(desiredTtlMs !== undefined ? { ttlMs: desiredTtlMs } : {}),
        remainingUses: Math.max(usesNeeded, desiredRemainingUses ?? usesNeeded),
      });

      const refreshed = await secureConfirmWorkerManager.confirmAndPrepareSigningSession({
        ctx,
        sessionId,
        kind: 'delegate',
        signingAuthMode: 'webauthn',
        sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
        nearAccountId,
        delegate: {
          senderId: delegate.senderId || nearAccountId,
          receiverId: delegate.receiverId,
          actions: actionsWasm,
          nonce: delegate.nonce,
          maxBlockHeight: delegate.maxBlockHeight,
        },
        rpcCall: resolvedRpcCall,
        confirmationConfigOverride,
        title,
        body,
      });

      intentDigest = refreshed.intentDigest;
      transactionContext = refreshed.transactionContext;
      credentialWithPrf = refreshed.credential as WebAuthnAuthenticationCredential | undefined;
      credentialForRelayJson = credentialWithPrf ? JSON.stringify(redactCredentialExtensionOutputs(credentialWithPrf)) : undefined;
      prfFirstB64u = getPrfResultsFromCredential(credentialWithPrf).first;
      if (!prfFirstB64u) {
        throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
      }
    }
  } else {
    prfFirstB64u = getPrfResultsFromCredential(credentialWithPrf).first;
    if (!prfFirstB64u) {
      throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
    }
  }

  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output for signing');
  }

  const delegatePayload = {
    senderId: delegate.senderId || nearAccountId,
    receiverId: delegate.receiverId,
    actions: actionsWasm,
    nonce: delegate.nonce.toString(),
    maxBlockHeight: delegate.maxBlockHeight.toString(),
    publicKey: signingContext.delegatePublicKeyStr,
  };

  if (!signingContext.threshold) {
    if (!localKeyMaterial) {
      throw new Error(`No local key material found for account: ${nearAccountId}`);
    }
    const response = await executeSignerWorkerOperation({
      ctx,
      kind: 'nearSigner',
      request: {
        sessionId,
        type: WorkerRequestType.SignDelegateAction,
        payload: {
          signerMode: signingContext.resolvedSignerMode,
          rpcCall: resolvedRpcCall,
          createdAt: Date.now(),
          prfFirstB64u,
          wrapKeySalt: localWrapKeySalt,
          decryption: {
            encryptedPrivateKeyData: localKeyMaterial.encryptedSk,
            encryptedPrivateKeyChacha20NonceB64u: localKeyMaterial.chacha20NonceB64u,
          },
          delegate: delegatePayload,
          intentDigest,
          transactionContext,
          credential: credentialForRelayJson,
        },
        onEvent,
      },
    });

    const okResponse = requireOkSignDelegateActionResponse(response);
    return {
      signedDelegate: okResponse.payload.signedDelegate!,
      hash: okResponse.payload.hash!,
      nearAccountId: toAccountId(nearAccountId),
      logs: [...(okResponse.payload.logs || []), ...warnings],
    };
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

    const expiresAtMs = minted.expiresAtMs ?? (Date.now() + thresholdSessionPlan.policy.ttlMs);
    const remainingUses = minted.remainingUses ?? thresholdSessionPlan.policy.remainingUses;

    if (!prfFirstB64u) {
      throw new Error('Missing PRF.first output for threshold session cache');
    }
    await secureConfirmWorkerManager.putPrfFirstForThresholdSession({
      sessionId,
      prfFirstB64u,
      expiresAtMs,
      remainingUses,
    }).catch(() => { });

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

  if (!signingContext.threshold.thresholdSessionJwt) {
    throw new Error('Missing thresholdSessionJwt for threshold delegate signing');
  }

  const requestPayload: Omit<WasmSignDelegateActionRequest, 'sessionId'> = {
    signerMode: signingContext.resolvedSignerMode,
    rpcCall: resolvedRpcCall,
    createdAt: Date.now(),
    prfFirstB64u,
    wrapKeySalt: thresholdWrapKeySalt,
    decryption: {
      encryptedPrivateKeyData: '',
      encryptedPrivateKeyChacha20NonceB64u: '',
    },
    threshold: {
      relayerUrl: signingContext.threshold.relayerUrl,
      relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
      clientParticipantId: signingContext.threshold.thresholdKeyMaterial.participants.find((p) => p.role === 'client')?.id,
      relayerParticipantId: signingContext.threshold.thresholdKeyMaterial.participants.find((p) => p.role === 'relayer')?.id,
      participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map((p) => p.id),
      thresholdSessionKind: 'jwt' as const,
      thresholdSessionJwt: signingContext.threshold.thresholdSessionJwt,
    },
    delegate: delegatePayload,
    intentDigest,
    transactionContext,
    credential: credentialForRelayJson,
  } as any;

  let okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignDelegateAction> | undefined;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const resp = await executeSignerWorkerOperation({
        ctx,
        kind: 'nearSigner',
        request: {
          sessionId,
          type: WorkerRequestType.SignDelegateAction,
          payload: requestPayload,
          onEvent,
        },
      });
      okResponse = requireOkSignDelegateActionResponse(resp);
      break;
    } catch (e: unknown) {
      const err = e instanceof Error ? e : new Error(String(e));

      if (canFallbackToLocal && isThresholdSignerMissingKeyError(err)) {
        if (!localKeyMaterial) throw new Error(`No local key material found for account: ${nearAccountId}`);
        const msg =
          '[WebAuthnManager] threshold-signer requested but the relayer is missing the signing share; falling back to local-signer';
        // eslint-disable-next-line no-console
        console.warn(msg);
        warnings.push(msg);

        try {
          clearCachedThresholdEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
        } catch { }
        signingContext.threshold.thresholdSessionJwt = undefined;

        const localPublicKey = ensureEd25519Prefix(localKeyMaterial.publicKey);
        if (!localPublicKey) {
          throw new Error(`Missing local signing public key for ${nearAccountId}`);
        }
        ctx.nonceManager.initializeUser(toAccountId(nearAccountId), localPublicKey);
        transactionContext = await ctx.nonceManager.getNonceBlockHashAndHeight(ctx.nearClient, { force: true });

        const localDelegatePayload = {
          ...delegatePayload,
          publicKey: localPublicKey,
        };

        const resp = await executeSignerWorkerOperation({
          ctx,
          kind: 'nearSigner',
          request: {
            sessionId,
            type: WorkerRequestType.SignDelegateAction,
            payload: {
              signerMode: 'local-signer',
              rpcCall: resolvedRpcCall,
              createdAt: Date.now(),
              prfFirstB64u,
              wrapKeySalt: localWrapKeySalt,
              decryption: {
                encryptedPrivateKeyData: localKeyMaterial.encryptedSk,
                encryptedPrivateKeyChacha20NonceB64u: localKeyMaterial.chacha20NonceB64u,
              },
              delegate: localDelegatePayload,
              intentDigest,
              transactionContext,
              credential: credentialForRelayJson,
            },
            onEvent,
          },
        });
        okResponse = requireOkSignDelegateActionResponse(resp);
        break;
      }

      if (attempt === 0 && isThresholdSessionAuthUnavailableError(err)) {
        clearCachedThresholdEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
        await secureConfirmWorkerManager.clearPrfFirstForThresholdSession({ sessionId }).catch(() => { });
        signingContext.threshold.thresholdSessionJwt = undefined;
        requestPayload.threshold!.thresholdSessionJwt = undefined;

        const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
        thresholdSessionPlan = await buildThresholdSessionPolicy({
          nearAccountId,
          rpId,
          relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
          participantIds: signingContext.threshold.thresholdKeyMaterial.participants.map((p) => p.id),
          ...(desiredTtlMs !== undefined ? { ttlMs: desiredTtlMs } : {}),
          remainingUses: Math.max(usesNeeded, desiredRemainingUses ?? usesNeeded),
        });

        const refreshed = await secureConfirmWorkerManager.confirmAndPrepareSigningSession({
          ctx,
          sessionId,
          kind: 'delegate',
          signingAuthMode: 'webauthn',
          sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
          nearAccountId,
          delegate: {
            senderId: delegate.senderId || nearAccountId,
            receiverId: delegate.receiverId,
            actions: actionsWasm,
            nonce: delegate.nonce,
            maxBlockHeight: delegate.maxBlockHeight,
          },
          rpcCall: resolvedRpcCall,
          confirmationConfigOverride,
          title,
          body,
        });

        intentDigest = refreshed.intentDigest;
        transactionContext = refreshed.transactionContext;
        credentialWithPrf = refreshed.credential as WebAuthnAuthenticationCredential | undefined;
        credentialForRelayJson = credentialWithPrf ? JSON.stringify(redactCredentialExtensionOutputs(credentialWithPrf)) : undefined;

        const prfFirst = getPrfResultsFromCredential(credentialWithPrf).first;
        if (!prfFirst) {
          throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
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

        const expiresAtMs = minted.expiresAtMs ?? (Date.now() + thresholdSessionPlan.policy.ttlMs);
        const remainingUses = minted.remainingUses ?? thresholdSessionPlan.policy.remainingUses;

        await secureConfirmWorkerManager.putPrfFirstForThresholdSession({
          sessionId,
          prfFirstB64u: prfFirst,
          expiresAtMs,
          remainingUses,
        }).catch(() => { });

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
        requestPayload.intentDigest = intentDigest;
        requestPayload.transactionContext = transactionContext;
        requestPayload.credential = credentialForRelayJson;
        continue;
      }

      throw err;
    }
  }

  if (!okResponse) {
    throw new Error('No delegate signing response received');
  }

  return {
    signedDelegate: okResponse.payload.signedDelegate!,
    hash: okResponse.payload.hash!,
    nearAccountId: toAccountId(nearAccountId),
    logs: [...(okResponse.payload.logs || []), ...warnings],
  };
}

type ThresholdDelegateSigningContext = {
  resolvedSignerMode: 'threshold-signer';
  signingNearPublicKeyStr: string;
  delegatePublicKeyStr: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519_2p_V1Material;
    thresholdSessionCacheKey: string;
    thresholdSessionJwt: string | undefined;
  };
};

type LocalDelegateSigningContext = {
  resolvedSignerMode: 'local-signer';
  signingNearPublicKeyStr: string;
  delegatePublicKeyStr: string;
  threshold: null;
};

type DelegateSigningContext = ThresholdDelegateSigningContext | LocalDelegateSigningContext;

function validateAndPrepareDelegateSigningContext(args: {
  nearAccountId: string;
  resolvedSignerMode: SignerMode['mode'];
  relayerUrl: string;
  rpId: string | null;
  localKeyMaterial: LocalNearSkV3Material | null;
  thresholdKeyMaterial: ThresholdEd25519_2p_V1Material | null;
  providedDelegatePublicKey: DelegateActionInput['publicKey'];
  warnings: string[];
}): DelegateSigningContext {
  const providedDelegatePublicKeyStr = ensureEd25519Prefix(toPublicKeyString(args.providedDelegatePublicKey));

  if (args.resolvedSignerMode !== 'threshold-signer') {
    if (!args.localKeyMaterial) {
      throw new Error(`No local key material found for account: ${args.nearAccountId}`);
    }
    const localPublicKey = ensureEd25519Prefix(args.localKeyMaterial.publicKey);
    if (!localPublicKey) {
      throw new Error(`Missing local signing public key for ${args.nearAccountId}`);
    }
    if (providedDelegatePublicKeyStr && providedDelegatePublicKeyStr !== localPublicKey) {
      args.warnings.push(
        `Delegate public key ${providedDelegatePublicKeyStr} does not match local signer key; using ${localPublicKey}`
      );
    }
    return {
      resolvedSignerMode: 'local-signer',
      signingNearPublicKeyStr: localPublicKey,
      delegatePublicKeyStr: localPublicKey,
      threshold: null,
    };
  }

  const thresholdKeyMaterial = args.thresholdKeyMaterial;
  if (!thresholdKeyMaterial) {
    throw new Error(`Missing threshold key material for ${args.nearAccountId}`);
  }

  const thresholdPublicKey = ensureEd25519Prefix(thresholdKeyMaterial.publicKey);
  if (!thresholdPublicKey) {
    throw new Error(`Missing threshold signing public key for ${args.nearAccountId}`);
  }

  if (providedDelegatePublicKeyStr && providedDelegatePublicKeyStr !== thresholdPublicKey) {
    args.warnings.push(
      `Delegate public key ${providedDelegatePublicKeyStr} does not match threshold signer key; using ${thresholdPublicKey}`
    );
  }

  const relayerUrl = String(args.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayerUrl (required for threshold-signer)');
  }

  const rpId = String(args.rpId || '').trim();
  if (!rpId) {
    throw new Error('Missing rpId for threshold signing');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(thresholdKeyMaterial.participants.map((p) => p.id));
  if (!participantIds || participantIds.length < 2) {
    throw new Error(
      `Invalid threshold signing participantIds (expected >=2 participants, got [${(participantIds || []).join(',')}])`
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
    signingNearPublicKeyStr: thresholdPublicKey,
    delegatePublicKeyStr: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
      thresholdSessionCacheKey,
      thresholdSessionJwt: getCachedThresholdEd25519AuthSessionJwt(thresholdSessionCacheKey),
    },
  };
}

function requireOkSignDelegateActionResponse(
  response: DelegateSignResponse
): WorkerSuccessResponse<typeof WorkerRequestType.SignDelegateAction> {
  if (!isSignDelegateActionSuccess(response)) {
    if (isWorkerError(response)) {
      throw new Error(response.payload.error || 'Delegate action signing failed');
    }
    throw new Error('Delegate action signing failed');
  }

  if (!response.payload.success || !response.payload.signedDelegate || !response.payload.hash) {
    throw new Error(response.payload.error || 'Delegate action signing failed');
  }
  return response;
}
