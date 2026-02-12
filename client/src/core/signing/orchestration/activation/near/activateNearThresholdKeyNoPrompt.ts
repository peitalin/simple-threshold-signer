import { IndexedDBManager } from '../../../../IndexedDBManager';
import { SignedTransaction } from '../../../../near/NearClient';
import { toAccountId } from '../../../../types/accountIds';
import type { AccountId } from '../../../../types/accountIds';
import type { TransactionContext } from '../../../../types/rpc';
import type { onProgressEvents } from '../../../../types/sdkSentEvents';
import {
  INTERNAL_WORKER_REQUEST_TYPE_SIGN_ADD_KEY_THRESHOLD_PUBLIC_KEY_NO_PROMPT,
  isSignAddKeyThresholdPublicKeyNoPromptSuccess,
} from '../../../../types/signer-worker';
import type { SignTransactionResult } from '../../../../types/tatchi';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../../../../types/webauthn';
import { ensureEd25519Prefix } from '../../../../../../../shared/src/utils/validation';
import { getPrfFirstB64uFromCredential } from '../../../webauthn/credentials/credentialExtensions';
import { getLastLoggedInDeviceNumber } from '../../../webauthn/device/getDeviceNumber';
import type { SignerWorkerManagerContext } from '../../../workers/signerWorkerManager';

export type ActivateNearThresholdKeyNoPromptRequest = {
  nearAccountId: AccountId | string;
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
  wrapKeySalt: string;
  transactionContext: TransactionContext;
  thresholdPublicKey: string;
  relayerVerifyingShareB64u: string;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  deviceNumber?: number;
  onEvent?: (update: onProgressEvents) => void;
};

export type ActivateNearThresholdKeyNoPromptDeps = {
  requestWorkerOperation: SignerWorkerManagerContext['requestWorkerOperation'];
  createSessionId?: (prefix: string) => string;
};

function createSessionId(prefix: string): string {
  return typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export async function activateNearThresholdKeyNoPrompt(
  deps: ActivateNearThresholdKeyNoPromptDeps,
  args: ActivateNearThresholdKeyNoPromptRequest,
): Promise<SignTransactionResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const wrapKeySalt = args.wrapKeySalt;
  if (!wrapKeySalt) throw new Error('Missing wrapKeySalt for AddKey(thresholdPublicKey) signing');
  if (!args.credential) throw new Error('Missing credential for AddKey(thresholdPublicKey) signing');
  if (!args.transactionContext) throw new Error('Missing transactionContext for no-prompt signing');

  const thresholdPublicKey = ensureEd25519Prefix(args.thresholdPublicKey);
  if (!thresholdPublicKey)
    throw new Error('Missing thresholdPublicKey for AddKey(thresholdPublicKey) signing');

  const relayerVerifyingShareB64u = args.relayerVerifyingShareB64u;
  if (!relayerVerifyingShareB64u)
    throw new Error('Missing relayerVerifyingShareB64u for AddKey(thresholdPublicKey) signing');

  const deviceNumber = Number(args.deviceNumber);
  const resolvedDeviceNumber =
    Number.isSafeInteger(deviceNumber) && deviceNumber >= 1
      ? deviceNumber
      : await getLastLoggedInDeviceNumber(nearAccountId, IndexedDBManager.clientDB);

  const localKeyMaterial = await IndexedDBManager.getNearLocalKeyMaterialV2First(
    nearAccountId,
    resolvedDeviceNumber,
  );
  if (!localKeyMaterial) {
    throw new Error(
      `No local key material found for account ${nearAccountId} device ${resolvedDeviceNumber}`,
    );
  }

  if (localKeyMaterial.wrapKeySalt !== wrapKeySalt) {
    throw new Error('wrapKeySalt mismatch for AddKey(thresholdPublicKey) signing');
  }

  const prfFirstB64u = getPrfFirstB64uFromCredential(args.credential);
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output for AddKey(thresholdPublicKey) signing');
  }

  const sessionId = (deps.createSessionId || createSessionId)('no-prompt-add-threshold-key');
  const response = await deps.requestWorkerOperation({
    kind: 'nearSigner',
    request: {
      sessionId,
      type: INTERNAL_WORKER_REQUEST_TYPE_SIGN_ADD_KEY_THRESHOLD_PUBLIC_KEY_NO_PROMPT,
      payload: {
        createdAt: Date.now(),
        decryption: {
          encryptedPrivateKeyData: localKeyMaterial.encryptedSk,
          encryptedPrivateKeyChacha20NonceB64u: localKeyMaterial.chacha20NonceB64u,
        },
        transactionContext: args.transactionContext,
        nearAccountId,
        thresholdPublicKey,
        relayerVerifyingShareB64u,
        clientParticipantId:
          typeof args.clientParticipantId === 'number' ? args.clientParticipantId : undefined,
        relayerParticipantId:
          typeof args.relayerParticipantId === 'number' ? args.relayerParticipantId : undefined,
        prfFirstB64u,
        wrapKeySalt,
      },
      onEvent: args.onEvent,
    },
  });

  if (!isSignAddKeyThresholdPublicKeyNoPromptSuccess(response)) {
    throw new Error('AddKey(thresholdPublicKey) signing failed');
  }
  if (!response.payload.success) {
    throw new Error(response.payload.error || 'AddKey(thresholdPublicKey) signing failed');
  }

  const signedTransactions = response.payload.signedTransactions || [];
  if (signedTransactions.length !== 1) {
    throw new Error(`Expected 1 signed transaction but received ${signedTransactions.length}`);
  }

  const signedTx = signedTransactions[0];
  if (!signedTx || !(signedTx as any).transaction || !(signedTx as any).signature) {
    throw new Error('Incomplete signed transaction data received for AddKey(thresholdPublicKey)');
  }

  return {
    signedTransaction: new SignedTransaction({
      transaction: (signedTx as any).transaction,
      signature: (signedTx as any).signature,
      borsh_bytes: Array.from((signedTx as any).borshBytes || []),
    }),
    nearAccountId: String(nearAccountId),
    logs: response.payload.logs || [],
  };
}
