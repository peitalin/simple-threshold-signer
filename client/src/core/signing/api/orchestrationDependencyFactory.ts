import { IndexedDBManager } from '../../IndexedDBManager';
import type { NearClient } from '../../near/NearClient';
import type { NonceManager } from '../../near/nonceManager';
import type { AccountId } from '../../types/accountIds';
import type { ThemeName, TatchiConfigs } from '../../types/tatchi';
import type { SecureConfirmWorkerManager } from '../secureConfirm/manager';
import type { TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManager } from '../workers/signerWorkerManager';
import type { FacadeConvenienceDeps } from './facadeConvenience';
import { createFacadeConvenienceDeps } from './facadeDependencyFactory';
import type { IndexedDbFacadeDeps } from './indexedDbFacade';
import type { NearKeyDerivationDeps } from './nearKeyDerivation';
import type { NearSigningApiDeps } from './nearSigning';
import type { PrivateKeyExportRecoveryDeps } from './privateKeyExportRecovery';
import type { RegistrationAccountLifecycleDeps } from './registrationAccountLifecycle';
import type { RegistrationSessionDeps } from './registrationSession';
import type { SignerWorkerBridgeDeps } from './signerWorkerBridge';
import {
  generateSessionId as generateSessionIdValue,
  getOrCreateActiveSigningSessionId as getOrCreateActiveSigningSessionIdValue,
  getWarmSigningSessionStatus as getWarmSigningSessionStatusValue,
  resolveSigningSessionPolicy as resolveSigningSessionPolicyValue,
  type SigningSessionStateDeps,
} from './signingSessionState';
import type { TempoSigningDeps } from './tempoSigning';
import type { ThresholdEd25519LifecycleDeps } from './thresholdEd25519Lifecycle';
import type { ThresholdSessionActivationDeps } from './thresholdSessionActivation';
import {
  prewarmSignerWorkers as prewarmSignerWorkersValue,
  warmCriticalResources as warmCriticalResourcesValue,
  type WorkerResourceWarmupDeps,
} from './workerResourceWarmup';
import type { UserPreferencesManager } from './userPreferences';

export type CreateOrchestrationDependencyBundleArgs = {
  tatchiPasskeyConfigs: TatchiConfigs;
  nearClient: NearClient;
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceManager: NonceManager;
  secureConfirmWorkerManager: SecureConfirmWorkerManager;
  signerWorkerManager: SignerWorkerManager;
  activeSigningSessionIds: Map<string, string>;
  getWorkerBaseOrigin: () => string;
  getTheme: () => ThemeName;
  signTempo: FacadeConvenienceDeps['signTempo'];
  signTransactionsWithActions: ThresholdEd25519LifecycleDeps['signTransactionsWithActions'];
  signNearWithIntent: NearSigningApiDeps['signNearWithIntent'];
  deriveNearKeypairFromCredentialViaWorker:
    PrivateKeyExportRecoveryDeps['deriveNearKeypairFromCredentialViaWorker'];
  extractCosePublicKey: RegistrationAccountLifecycleDeps['extractCosePublicKey'];
  initializeCurrentUser: WorkerResourceWarmupDeps['initializeCurrentUser'];
  persistThresholdEcdsaBootstrapChainAccount:
    ThresholdSessionActivationDeps['persistThresholdEcdsaBootstrapChainAccount'];
};

export type OrchestrationDependencyBundle = {
  thresholdEd25519LifecycleDeps: ThresholdEd25519LifecycleDeps;
  nearSigningDeps: NearSigningApiDeps;
  tempoSigningDeps: TempoSigningDeps;
  privateKeyExportRecoveryDeps: PrivateKeyExportRecoveryDeps;
  nearKeyDerivationDeps: NearKeyDerivationDeps;
  registrationAccountLifecycleDeps: RegistrationAccountLifecycleDeps;
  registrationSessionDeps: RegistrationSessionDeps;
  indexedDbFacadeDeps: IndexedDbFacadeDeps;
  signingSessionStateDeps: SigningSessionStateDeps;
  thresholdSessionActivationDeps: ThresholdSessionActivationDeps;
  signerWorkerBridgeDeps: SignerWorkerBridgeDeps;
  getWorkerResourceWarmupDeps: () => WorkerResourceWarmupDeps;
  getFacadeConvenienceDeps: () => FacadeConvenienceDeps;
};

export function createOrchestrationDependencyBundle(
  args: CreateOrchestrationDependencyBundleArgs,
): OrchestrationDependencyBundle {
  const signingSessionStateDeps: SigningSessionStateDeps = {
    activeSigningSessionIds: args.activeSigningSessionIds,
    secureConfirmWorkerManager: args.secureConfirmWorkerManager,
    createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    signingSessionDefaults: args.tatchiPasskeyConfigs.signingSessionDefaults,
  };
  const getOrCreateActiveSigningSessionId = (nearAccountId: AccountId): string =>
    getOrCreateActiveSigningSessionIdValue(signingSessionStateDeps, nearAccountId);

  const nearSigningDeps: NearSigningApiDeps = {
    contractId: args.tatchiPasskeyConfigs.contractId,
    nearRpcUrl: args.tatchiPasskeyConfigs.nearRpcUrl,
    resolveSigningSessionPolicy: (policyArgs) =>
      resolveSigningSessionPolicyValue(signingSessionStateDeps, policyArgs),
    getOrCreateActiveSigningSessionId: getOrCreateActiveSigningSessionId,
    getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
    signNearWithIntent: args.signNearWithIntent,
  };

  const getWorkerResourceWarmupDeps = (): WorkerResourceWarmupDeps => ({
    workerBaseOrigin: args.getWorkerBaseOrigin(),
    indexedDB: IndexedDBManager,
    nearClient: args.nearClient,
    nonceManager: args.nonceManager,
    preWarmWorkerPool: args.signerWorkerManager.preWarmWorkerPool.bind(args.signerWorkerManager),
    initializeCurrentUser: args.initializeCurrentUser,
  });

  return {
    thresholdEd25519LifecycleDeps: {
      indexedDB: IndexedDBManager,
      touchIdPrompt: args.touchIdPrompt,
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
      getSignerWorkerRequestOperation: () =>
        args.signerWorkerManager.getContext().requestWorkerOperation,
      createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
      nearClient: args.nearClient,
      nonceManager: args.nonceManager,
      relayerUrl: args.tatchiPasskeyConfigs.relayer.url,
      contractId: args.tatchiPasskeyConfigs.contractId,
      nearRpcUrl: args.tatchiPasskeyConfigs.nearRpcUrl,
      signTransactionsWithActions: args.signTransactionsWithActions,
    },
    nearSigningDeps: nearSigningDeps,
    tempoSigningDeps: {
      indexedDB: IndexedDBManager,
      tatchiPasskeyConfigs: args.tatchiPasskeyConfigs,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      secureConfirmWorkerManager: args.secureConfirmWorkerManager,
    },
    privateKeyExportRecoveryDeps: {
      indexedDB: IndexedDBManager,
      secureConfirmWorkerManager: args.secureConfirmWorkerManager,
      getTheme: args.getTheme,
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
      deriveNearKeypairFromCredentialViaWorker:
        args.deriveNearKeypairFromCredentialViaWorker,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    },
    nearKeyDerivationDeps: {
      createSessionId: (prefix: string): string => generateSessionIdValue(prefix),
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
    },
    registrationAccountLifecycleDeps: {
      indexedDB: IndexedDBManager,
      userPreferencesManager: args.userPreferencesManager,
      nonceManager: args.nonceManager,
      extractCosePublicKey: args.extractCosePublicKey,
    },
    registrationSessionDeps: {
      contractId: args.tatchiPasskeyConfigs.contractId,
      nearRpcUrl: args.tatchiPasskeyConfigs.nearRpcUrl,
      secureConfirmWorkerManager: args.secureConfirmWorkerManager,
      touchIdPrompt: args.touchIdPrompt,
    },
    indexedDbFacadeDeps: {
      indexedDB: IndexedDBManager,
    },
    signingSessionStateDeps: signingSessionStateDeps,
    thresholdSessionActivationDeps: {
      indexedDB: IndexedDBManager,
      touchIdPrompt: args.touchIdPrompt,
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
      secureConfirmWorkerManager: args.secureConfirmWorkerManager,
      getSignerWorkerContext: () => args.signerWorkerManager.getContext(),
      getOrCreateActiveSigningSessionId: getOrCreateActiveSigningSessionId,
      defaultRelayerUrl: args.tatchiPasskeyConfigs.relayer?.url || '',
      persistThresholdEcdsaBootstrapChainAccount:
        args.persistThresholdEcdsaBootstrapChainAccount,
    },
    signerWorkerBridgeDeps: {
      signingKeyOps: args.signerWorkerManager.nearKeyOps,
    },
    getWorkerResourceWarmupDeps: getWorkerResourceWarmupDeps,
    getFacadeConvenienceDeps: (): FacadeConvenienceDeps =>
      createFacadeConvenienceDeps({
        signTempo: args.signTempo,
        prewarmSignerWorkers: () =>
          prewarmSignerWorkersValue(getWorkerResourceWarmupDeps()),
        warmCriticalResources: (nearAccountId?: string) =>
          warmCriticalResourcesValue(getWorkerResourceWarmupDeps(), nearAccountId),
        getWarmSigningSessionStatus: (nearAccountId: AccountId | string) =>
          getWarmSigningSessionStatusValue(signingSessionStateDeps, nearAccountId),
      }),
  };
}
