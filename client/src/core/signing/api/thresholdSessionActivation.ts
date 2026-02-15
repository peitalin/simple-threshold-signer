import type { UnifiedIndexedDBManager } from '../../IndexedDBManager';
import { toAccountId, type AccountId } from '../../types/accountIds';
import type { SecureConfirmWorkerManager } from '../secureConfirm/manager';
import type { TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManagerContext } from '../workers/signerWorkerManager';
import type { NearSigningKeyOpsService } from '../workers/signerWorkerManager/nearKeyOpsService';
import { connectThresholdEd25519SessionLite } from '../threshold/workflows/connectThresholdEd25519SessionLite';
import {
  activateEvmThresholdEcdsaSessionLite,
  activateTempoThresholdEcdsaSessionLite,
  activateThresholdKeyForChain,
  type ThresholdEcdsaActivationChain,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../orchestration/activation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from './thresholdEcdsaBootstrapPersistence';

type PutPrfFirstForThresholdSessionArgs = Parameters<
  SecureConfirmWorkerManager['putPrfFirstForThresholdSession']
>[0];

export type ConnectThresholdEd25519SessionLiteArgs = {
  nearAccountId: AccountId | string;
  relayerKeyId: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  relayerUrl?: string;
  ttlMs?: number;
  remainingUses?: number;
};

export type BootstrapThresholdEcdsaSessionLiteArgs = {
  nearAccountId: AccountId | string;
  chain?: ThresholdEcdsaActivationChain;
  relayerUrl?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  ttlMs?: number;
  remainingUses?: number;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
};

export type ThresholdSessionActivationDeps = {
  indexedDB: UnifiedIndexedDBManager;
  touchIdPrompt: Pick<TouchIdPrompt, 'getRpId' | 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
  signingKeyOps: Pick<NearSigningKeyOpsService, 'deriveThresholdEd25519ClientVerifyingShare'>;
  secureConfirmWorkerManager: Pick<
    SecureConfirmWorkerManager,
    'putPrfFirstForThresholdSession'
  >;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  getOrCreateActiveSigningSessionId: (nearAccountId: AccountId) => string;
  defaultRelayerUrl: string;
  persistThresholdEcdsaBootstrapChainAccount: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }) => Promise<void>;
};

function resolveRelayerUrl(relayerUrlOverride: string | undefined, defaultRelayerUrl: string): string {
  const relayerUrl = String(relayerUrlOverride || defaultRelayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayer url (configs.relayer.url)');
  }
  return relayerUrl;
}

export async function connectThresholdEd25519SessionLiteValue(
  deps: ThresholdSessionActivationDeps,
  args: ConnectThresholdEd25519SessionLiteArgs,
): Promise<Awaited<ReturnType<typeof connectThresholdEd25519SessionLite>>> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const relayerUrl = resolveRelayerUrl(args.relayerUrl, deps.defaultRelayerUrl);
  const sessionId = deps.getOrCreateActiveSigningSessionId(nearAccountId);
  return await connectThresholdEd25519SessionLite({
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    signingKeyOps: deps.signingKeyOps,
    prfFirstCache: {
      putPrfFirstForThresholdSession: (params: PutPrfFirstForThresholdSessionArgs) =>
        deps.secureConfirmWorkerManager.putPrfFirstForThresholdSession(params),
    },
    relayerUrl,
    relayerKeyId: args.relayerKeyId,
    nearAccountId,
    participantIds: args.participantIds,
    sessionKind: args.sessionKind,
    sessionId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  });
}

export async function bootstrapThresholdEcdsaSessionLiteValue(
  deps: ThresholdSessionActivationDeps,
  args: BootstrapThresholdEcdsaSessionLiteArgs,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const chain: ThresholdEcdsaActivationChain = args.chain || 'tempo';
  const relayerUrl = resolveRelayerUrl(args.relayerUrl, deps.defaultRelayerUrl);

  const signerWorkerCtx = deps.getSignerWorkerContext();
  const activationDeps = {
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    prfFirstCache: {
      putPrfFirstForThresholdSession: (params: PutPrfFirstForThresholdSessionArgs) =>
        deps.secureConfirmWorkerManager.putPrfFirstForThresholdSession(params),
    },
    workerCtx: signerWorkerCtx,
    getOrCreateActiveSigningSessionId: deps.getOrCreateActiveSigningSessionId,
  };

  const bootstrap = await activateThresholdKeyForChain({
    chain,
    adapters: {
      evm: (request) => activateEvmThresholdEcdsaSessionLite(activationDeps, request),
      tempo: (request) => activateTempoThresholdEcdsaSessionLite(activationDeps, request),
    },
    request: {
      nearAccountId,
      relayerUrl,
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
    },
  });

  await deps.persistThresholdEcdsaBootstrapChainAccount({
    nearAccountId,
    chain,
    bootstrap,
    smartAccount: args.smartAccount,
  });
  return bootstrap;
}
