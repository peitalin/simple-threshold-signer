
import { SignedTransaction } from '../../../NearClient';
import { TransactionInputWasm, validateActionArgsWasm } from '../../../types/actions';
import { type onProgressEvents } from '../../../types/sdkSentEvents';
import {
  WorkerRequestType,
  TransactionPayload,
  type WasmSignTransactionsWithActionsRequest,
  isSignTransactionsWithActionsSuccess,
  isWorkerError,
  type ConfirmationConfig,
  type RpcCallPayload,
  type SignerMode,
  type TransactionResponse,
  type WorkerSuccessResponse,
  getThresholdBehaviorFromSignerMode,
} from '../../../types/signer-worker';
import { AccountId } from '../../../types/accountIds';
import { SignerWorkerManagerContext } from '..';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '../../../defaultConfigs2';
import { toAccountId } from '../../../types/accountIds';
import { getLastLoggedInDeviceNumber } from '../getDeviceNumber';
import { WebAuthnAuthenticationCredential } from '../../../types';
import { removePrfOutputGuard } from '../../credentialsHelpers';
import { isRelayerThresholdEd25519Configured, resolveSignerModeForThresholdSigning } from '../../../threshold/thresholdEd25519RelayerHealth';
import type { TransactionContext } from '../../../types/rpc';
import type {
  LocalNearSkV3Material,
  ThresholdEd25519_2p_V1Material,
} from '../../../IndexedDBManager/passkeyNearKeysDB';
import {
  clearCachedThresholdEd25519AuthSession,
  getCachedThresholdEd25519AuthSessionJwt,
  makeThresholdEd25519AuthSessionCacheKey,
  mintThresholdEd25519AuthSessionLite,
  putCachedThresholdEd25519AuthSession,
} from '../../../threshold/thresholdEd25519AuthSession';
import type { SigningAuthMode } from '../../SecureConfirmWorkerManager/confirmTxFlow/types';
import {
  buildThresholdSessionPolicy,
  isThresholdSessionAuthUnavailableError,
  isThresholdSignerMissingKeyError,
} from '../../../threshold/thresholdSessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '../../../../threshold/participants';
import { deriveThresholdEd25519ClientVerifyingShare } from './deriveThresholdEd25519ClientVerifyingShare';

/**
 * Sign multiple transactions with a shared WebAuthn credential.
 * Efficiently processes multiple transactions with one PRF-backed signing session.
 */

function getPrfResultsFromCredential(credential: unknown): { first?: string; second?: string } {
  try {
    const results = (credential as any)?.clientExtensionResults?.prf?.results as unknown;
    if (!results || typeof results !== 'object') return {};
    const first = typeof (results as any).first === 'string' ? (results as any).first.trim() : '';
    const second = typeof (results as any).second === 'string' ? (results as any).second.trim() : '';
    return {
      ...(first ? { first } : {}),
      ...(second ? { second } : {}),
    };
  } catch {
    return {};
  }
}

function generateSessionId(): string {
  return `sess-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

const DUMMY_WRAP_KEY_SALT_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export async function signTransactionsWithActions({
  ctx,
  sessionId: providedSessionId,
  transactions,
  rpcCall,
  signerMode,
  onEvent,
  confirmationConfigOverride,
  title,
  body,
  signingSessionTtlMs,
  signingSessionRemainingUses,
}: {
  ctx: SignerWorkerManagerContext,
  sessionId?: string;
  transactions: TransactionInputWasm[],
  rpcCall: RpcCallPayload;
  signerMode: SignerMode;
  onEvent?: (update: onProgressEvents) => void;
  // Allow callers to pass a partial override (e.g., { uiMode: 'drawer' })
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signingSessionTtlMs?: number;
  signingSessionRemainingUses?: number;
}): Promise<Array<{
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[]
}>> {

  const sessionId = providedSessionId ?? generateSessionId();
  const nearAccountId = rpcCall.nearAccountId;
  const relayerUrl = ctx.relayerUrl;

  transactions.forEach(txPayload => {
    txPayload.actions.forEach(action => {
      validateActionArgsWasm(action);
    })
  })

  const deviceNumber = await getLastLoggedInDeviceNumber(nearAccountId, ctx.indexedDB.clientDB);

  // Retrieve threshold key data first; local key material is only loaded when needed.
  const thresholdKeyMaterial = await ctx.indexedDB.nearKeysDB.getThresholdKeyMaterial(nearAccountId, deviceNumber);

  const warnings: string[] = [];
  const thresholdBehavior = getThresholdBehaviorFromSignerMode(signerMode);
  let resolvedSignerMode = await resolveSignerModeForThresholdSigning({
    nearAccountId,
    signerMode,
    relayerUrl,
    hasThresholdKeyMaterial: !!thresholdKeyMaterial,
    warnings,
  });

  const localKeyMaterial = (resolvedSignerMode === 'local-signer' || thresholdBehavior === 'fallback')
    ? await ctx.indexedDB.nearKeysDB.getLocalKeyMaterial(nearAccountId, deviceNumber)
    : null;
  const localWrapKeySalt = String(localKeyMaterial?.wrapKeySalt || '').trim();
  // Threshold share derivation must use the same wrapKeySalt that was used at keygen time.
  const thresholdWrapKeySalt = String(thresholdKeyMaterial?.wrapKeySalt || '').trim() || DUMMY_WRAP_KEY_SALT_B64U;

  // If the caller defaulted to local-signer but the account is threshold-only, prefer threshold-signer.
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

  console.debug('[signTransactionsWithActions] resolvedSignerMode', { nearAccountId, resolvedSignerMode, warnings });

  if (resolvedSignerMode === 'local-signer') {
    if (!localKeyMaterial) {
      throw new Error(`No local key material found for account: ${nearAccountId}`);
    }
    if (!localWrapKeySalt) {
      throw new Error(`Missing wrapKeySalt for account: ${nearAccountId}`);
    }
  }

  const canFallbackToLocal = thresholdBehavior === 'fallback' && !!localKeyMaterial && !!localWrapKeySalt;

  const signingContext = validateAndPrepareSigningContext({
    nearAccountId,
    resolvedSignerMode,
    relayerUrl,
    rpId: ctx.touchIdPrompt.getRpId(),
    localKeyMaterial,
    thresholdKeyMaterial,
  });

  // Ensure nonce/block context is fetched for the same access key that will sign.
  // Threshold signing MUST use the threshold/group public key (relayer access key) for:
  // - correct nonce reservation
  // - relayer scope checks (/authorize expects signingPayload.transactionContext.nearPublicKeyStr == relayer key)
  ctx.nonceManager.initializeUser(toAccountId(nearAccountId), signingContext.signingNearPublicKeyStr);

  // Normalize rpcCall to ensure required fields are present.
  const resolvedRpcCall = {
    contractId: rpcCall.contractId || PASSKEY_MANAGER_DEFAULT_CONFIGS.contractId,
    nearRpcUrl: rpcCall.nearRpcUrl || PASSKEY_MANAGER_DEFAULT_CONFIGS.nearRpcUrl,
    nearAccountId: rpcCall.nearAccountId,
  } as RpcCallPayload;

  // Create transaction signing requests (shared by local + threshold signing).
  // NOTE: nonce and blockHash are computed in confirmation flow, not here.
  const txSigningRequests: TransactionPayload[] = transactions.map(tx => ({
    nearAccountId: rpcCall.nearAccountId,
    receiverId: tx.receiverId,
    actions: tx.actions,
  }));

  // SecureConfirm before sending anything to the signer worker.
  // WebAuthn uses a challenge digest (threshold sessions use `sessionPolicyDigest32`).
  if (!ctx.secureConfirmWorkerManager) {
    throw new Error('SecureConfirmWorkerManager not available for signing');
  }
  const secureConfirmWorkerManager = ctx.secureConfirmWorkerManager;
  const usesNeeded = Math.max(1, txSigningRequests.length);
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
      const peek = await ctx.secureConfirmWorkerManager.peekPrfFirstForThresholdSession({ sessionId });
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
  const confirmation = await ctx.secureConfirmWorkerManager.confirmAndPrepareSigningSession({
    ctx,
    sessionId,
    kind: 'transaction',
    ...(signingAuthMode ? { signingAuthMode } : {}),
    ...(thresholdSessionPlan ? { sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32 } : {}),
    txSigningRequests: transactions,
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
    ? JSON.stringify(removePrfOutputGuard(credentialWithPrf))
    : undefined;

  let prfFirstB64u: string | undefined;

  // Resolve PRF.first for signer worker.
  if (signingContext.threshold && signingAuthMode === 'warmSession') {
    const delivered = await secureConfirmWorkerManager.dispensePrfFirstForThresholdSession({
      sessionId,
      uses: usesNeeded,
    });
    if (delivered.ok) {
      prfFirstB64u = delivered.prfFirstB64u;
    } else {
      // Warm session failed (expired/exhausted). Fall back to WebAuthn.
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
        kind: 'transaction',
        signingAuthMode: 'webauthn',
        sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
        txSigningRequests: transactions,
        rpcCall: resolvedRpcCall,
        confirmationConfigOverride,
        title,
        body,
      });

      intentDigest = refreshed.intentDigest;
      transactionContext = refreshed.transactionContext;
      credentialWithPrf = refreshed.credential as WebAuthnAuthenticationCredential | undefined;
      credentialForRelayJson = credentialWithPrf ? JSON.stringify(removePrfOutputGuard(credentialWithPrf)) : undefined;

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

  // Threshold signer: if we're not using a warm session token, mint a fresh relay threshold session (lite).
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
      const err = new Error(minted.message || minted.code || 'Failed to mint threshold session');
      // In fallback mode, allow missing relayer shares to degrade to local signing.
      // Missing relayer shares can cause the session mint to fail before the signer worker
      // ever attempts `/threshold-ed25519/authorize`.
      if (canFallbackToLocal && isThresholdSignerMissingKeyError(err)) {
        if (!localKeyMaterial) throw new Error(`No local key material found for account: ${nearAccountId}`);
        const msg =
          '[WebAuthnManager] threshold-signer requested but the relayer is missing the signing share; falling back to local-signer';
        // eslint-disable-next-line no-console
        console.warn(msg);
        warnings.push(msg);

        try { clearCachedThresholdEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey); } catch { }
        signingContext.threshold.thresholdSessionJwt = undefined;

        ctx.nonceManager.initializeUser(toAccountId(nearAccountId), localKeyMaterial.publicKey);
        const localTxContext = await ctx.nonceManager.getNonceBlockHashAndHeight(ctx.nearClient, { force: true });

        return await signTransactionsWithActionsLocally({
          ctx,
          sessionId,
          onEvent,
          resolvedRpcCall,
          localKeyMaterial,
          txSigningRequests,
          intentDigest,
          transactionContext: localTxContext,
          credential: credentialForRelayJson,
          prfFirstB64u,
          wrapKeySalt: localWrapKeySalt,
          expectedTransactionCount: transactions.length,
          warnings,
        });
      }
      throw err;
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

  // Threshold signer: authorize with relayer and pass threshold config into the signer worker.
  if (signingContext.threshold) {
    if (!signingContext.threshold.thresholdSessionJwt) {
      throw new Error('Missing thresholdSessionJwt for threshold signing');
    }
    const requestPayload: Omit<WasmSignTransactionsWithActionsRequest, 'sessionId'> = {
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
      txSigningRequests,
      intentDigest,
      transactionContext,
      credential: credentialForRelayJson,
    } as any;

    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await ctx.sendMessage<typeof WorkerRequestType.SignTransactionsWithActions>({
          sessionId,
          message: { type: WorkerRequestType.SignTransactionsWithActions, payload: requestPayload },
          onEvent,
        });
        const okResponse = requireOkSignTransactionsWithActionsResponse(response);
        return toSignedTransactionResults({
          okResponse,
          expectedTransactionCount: transactions.length,
          nearAccountId,
          warnings,
        });
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
          requestPayload.threshold!.thresholdSessionJwt = undefined;

          ctx.nonceManager.initializeUser(toAccountId(nearAccountId), localKeyMaterial.publicKey);
          transactionContext = await ctx.nonceManager.getNonceBlockHashAndHeight(ctx.nearClient, { force: true });

          return await signTransactionsWithActionsLocally({
            ctx,
            sessionId,
            onEvent,
            resolvedRpcCall,
            localKeyMaterial,
            txSigningRequests,
            intentDigest,
            transactionContext,
            credential: credentialForRelayJson,
            prfFirstB64u,
            wrapKeySalt: localWrapKeySalt,
            expectedTransactionCount: transactions.length,
            warnings,
          });
        }

        if (attempt === 0 && isThresholdSessionAuthUnavailableError(err)) {
          clearCachedThresholdEd25519AuthSession(signingContext.threshold.thresholdSessionCacheKey);
          await secureConfirmWorkerManager.clearPrfFirstForThresholdSession({ sessionId }).catch(() => { });
          signingContext.threshold.thresholdSessionJwt = undefined;
          requestPayload.threshold!.thresholdSessionJwt = undefined;

          // Re-mint a fresh threshold session (lite) and retry.
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
            kind: 'transaction',
            signingAuthMode: 'webauthn',
            sessionPolicyDigest32: thresholdSessionPlan.sessionPolicyDigest32,
            txSigningRequests: transactions,
            rpcCall: resolvedRpcCall,
            confirmationConfigOverride,
            title,
            body,
          });

          intentDigest = refreshed.intentDigest;
          transactionContext = refreshed.transactionContext;
          credentialWithPrf = refreshed.credential as WebAuthnAuthenticationCredential | undefined;
          credentialForRelayJson = credentialWithPrf ? JSON.stringify(removePrfOutputGuard(credentialWithPrf)) : undefined;

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
  }

  return await signTransactionsWithActionsLocally({
    ctx,
    sessionId,
    onEvent,
    resolvedRpcCall,
    localKeyMaterial: (() => {
      if (!localKeyMaterial) throw new Error(`No local key material found for account: ${nearAccountId}`);
      return localKeyMaterial;
    })(),
    txSigningRequests,
    intentDigest,
    transactionContext,
    credential: credentialForRelayJson,
    prfFirstB64u,
    wrapKeySalt: localWrapKeySalt,
    expectedTransactionCount: transactions.length,
    warnings,
  });

}

async function signTransactionsWithActionsLocally(args: {
  ctx: SignerWorkerManagerContext;
  sessionId: string;
  onEvent?: (update: onProgressEvents) => void;
  resolvedRpcCall: RpcCallPayload;
  localKeyMaterial: LocalNearSkV3Material;
  txSigningRequests: TransactionPayload[];
  intentDigest: string;
  transactionContext: TransactionContext;
  credential: string | undefined;
  prfFirstB64u: string | undefined;
  wrapKeySalt: string;
  expectedTransactionCount: number;
  warnings: string[];
}): Promise<Array<{
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
}>> {
  const response = await args.ctx.sendMessage<WorkerRequestType.SignTransactionsWithActions>({
    sessionId: args.sessionId,
    message: {
      type: WorkerRequestType.SignTransactionsWithActions,
      payload: {
        signerMode: 'local-signer',
        rpcCall: args.resolvedRpcCall,
        createdAt: Date.now(),
        prfFirstB64u: args.prfFirstB64u,
        wrapKeySalt: args.wrapKeySalt,
        decryption: {
          encryptedPrivateKeyData: args.localKeyMaterial.encryptedSk,
          encryptedPrivateKeyChacha20NonceB64u: args.localKeyMaterial.chacha20NonceB64u,
        },
        txSigningRequests: args.txSigningRequests,
        intentDigest: args.intentDigest,
        transactionContext: args.transactionContext,
        credential: args.credential,
      } as any,
    },
    onEvent: args.onEvent,
  });

  const okResponse = requireOkSignTransactionsWithActionsResponse(response);
  return toSignedTransactionResults({
    okResponse,
    expectedTransactionCount: args.expectedTransactionCount,
    nearAccountId: args.resolvedRpcCall.nearAccountId,
    warnings: args.warnings,
  });
}

function toSignedTransactionResults(args: {
  okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
  expectedTransactionCount: number;
  nearAccountId: string;
  warnings: string[];
}): Array<{
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
}> {
  const signedTransactions = args.okResponse.payload.signedTransactions || [];
  if (signedTransactions.length !== args.expectedTransactionCount) {
    throw new Error(
      `Expected ${args.expectedTransactionCount} signed transactions but received ${signedTransactions.length}`
    );
  }

  return signedTransactions.map((signedTx, index) => {
    if (!signedTx || !signedTx.transaction || !signedTx.signature) {
      throw new Error(`Incomplete signed transaction data received for transaction ${index + 1}`);
    }
    return {
      signedTransaction: new SignedTransaction({
        transaction: signedTx.transaction,
        signature: signedTx.signature,
        borsh_bytes: Array.from(signedTx.borshBytes || []),
      }),
      nearAccountId: toAccountId(args.nearAccountId),
      logs: [...(args.okResponse.payload.logs || []), ...args.warnings],
    };
  });
}

type ThresholdSigningContext = {
  resolvedSignerMode: 'threshold-signer';
  signingNearPublicKeyStr: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519_2p_V1Material;
    thresholdSessionCacheKey: string;
    thresholdSessionJwt: string | undefined;
  };
};

type LocalSigningContext = {
  resolvedSignerMode: 'local-signer';
  signingNearPublicKeyStr: string;
  threshold: null;
};

type SigningContext = ThresholdSigningContext | LocalSigningContext;

function validateAndPrepareSigningContext(args: {
  nearAccountId: string;
  resolvedSignerMode: SignerMode['mode'];
  relayerUrl: string;
  rpId: string | null;
  localKeyMaterial: LocalNearSkV3Material | null;
  thresholdKeyMaterial: ThresholdEd25519_2p_V1Material | null;
}): SigningContext {
  if (args.resolvedSignerMode !== 'threshold-signer') {
    if (!args.localKeyMaterial) {
      throw new Error(`No local key material found for account: ${args.nearAccountId}`);
    }
    const localPublicKey = String(args.localKeyMaterial.publicKey || '').trim();
    if (!localPublicKey) {
      throw new Error(`Missing local signing public key for ${args.nearAccountId}`);
    }
    return { resolvedSignerMode: 'local-signer', signingNearPublicKeyStr: localPublicKey, threshold: null };
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
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
      thresholdSessionCacheKey,
      thresholdSessionJwt: getCachedThresholdEd25519AuthSessionJwt(thresholdSessionCacheKey),
    },
  };
}

function requireOkSignTransactionsWithActionsResponse(
  response: TransactionResponse
): WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions> {
  if (!isSignTransactionsWithActionsSuccess(response)) {
    if (isWorkerError(response)) {
      throw new Error(response.payload.error || 'Batch transaction signing failed');
    }
    throw new Error('Batch transaction signing failed');
  }

  if (!response.payload.success) {
    throw new Error(response.payload.error || 'Batch transaction signing failed');
  }
  return response;
}
