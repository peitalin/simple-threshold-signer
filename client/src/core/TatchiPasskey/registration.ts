import type { NearClient } from '../near/NearClient';
import { ensureEd25519Prefix, validateNearAccountId } from '../../../../shared/src/utils/validation';
import type {
  RegistrationHooksOptions,
  RegistrationSSEEvent,
} from '../types/sdkSentEvents';
import type { RegistrationResult, TatchiConfigs } from '../types/tatchi';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import { RegistrationPhase, RegistrationStatus } from '../types/sdkSentEvents';
import {
  createAccountAndRegisterWithRelayServer
} from './faucets/createAccountRelayServer';
import { PasskeyManagerContext } from './index';
import { WebAuthnManager } from '../signing/api/WebAuthnManager';
import { IndexedDBManager } from '../IndexedDBManager';
import { type ConfirmationConfig, mergeSignerMode } from '../types/signer-worker';
import type { AccountId } from '../types/accountIds';
import { getUserFriendlyErrorMessage } from '../../../../shared/src/utils/errors';
import { buildThresholdEd25519Participants2pV1 } from '../../../../shared/src/threshold/participants';
import { checkNearAccountExistsBestEffort } from '../near/rpcCalls';
// Registration forces a visible, clickable confirmation for cross‑origin safety

/**
 * Core registration function that handles passkey registration
 *
 * Legacy proof-derived flows have been removed from the lite threshold-signer stack. Registration is now:
 * 1) Collect a standard WebAuthn registration credential (passkey).
 * 2) Derive a deterministic threshold client verifying share from PRF.first (default registration policy).
 *    Optionally derive/store encrypted local NEAR key material (v3 vault) as backup/export data.
 * 3) Create/register the account via the relayer using threshold key enrollment.
 */
export async function registerPasskeyInternal(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  options: RegistrationHooksOptions,
  authenticatorOptions: AuthenticatorOptions,
  confirmationConfigOverride?: Partial<ConfirmationConfig>
): Promise<RegistrationResult> {

  const { onEvent, onError, afterCall } = options;
  const { webAuthnManager, configs } = context;

  // Track registration progress for rollback
  const registrationState = {
    accountCreated: false,
    contractRegistered: false,
    databaseStored: false,
    contractTransactionId: null as string | null,
  };

  console.log('⚡ Registration: Passkey registration (standard WebAuthn)');
  onEvent?.({
    step: 1,
    phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
    status: RegistrationStatus.PROGRESS,
    message: `Starting registration for ${nearAccountId}`
  } as RegistrationSSEEvent);

  try {

    await validateRegistrationInputs(context, nearAccountId, onEvent, onError);

    onEvent?.({
      step: 1,
      phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
      status: RegistrationStatus.PROGRESS,
      message: 'Generating passkey credential...'
    });

    const confirmationConfig: Partial<ConfirmationConfig> = {
      uiMode: 'modal',
      behavior: 'requireClick', // cross‑origin safari requirement: must requireClick
      ...(confirmationConfigOverride ?? options?.confirmationConfig ?? {}),
    };

    const registrationSession = await context.webAuthnManager.requestRegistrationCredentialConfirmation({
      nearAccountId: String(nearAccountId),
      deviceNumber: 1,
      confirmerText: options?.confirmerText,
      confirmationConfigOverride: confirmationConfig,
    });

    const credential = registrationSession.credential;

    onEvent?.({
      step: 1,
      phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
      status: RegistrationStatus.SUCCESS,
      message: 'WebAuthn ceremony successful'
    });

    const baseSignerMode = webAuthnManager.getUserPreferences().getSignerMode();
    // Registration defaults to threshold mode even when global/user defaults are local-signer.
    // Explicit per-call overrides can still force local mode for legacy compatibility.
    const registrationDefaultSignerMode = baseSignerMode.mode === 'threshold-signer'
      ? baseSignerMode
      : { mode: 'threshold-signer' as const };
    const requestedSignerMode = mergeSignerMode(registrationDefaultSignerMode, options?.signerMode);
    const requestedSignerModeStr = requestedSignerMode.mode;
    const deriveLocalBackupKey = requestedSignerModeStr === 'threshold-signer'
      ? options?.backupLocalKey !== false
      : true;

    const deviceNumber = 1;
    let accountNearPublicKey: string | null = null;
    let thresholdClientVerifyingShareB64u: string | null = null;
    let localKeyMaterialForPersist: {
      publicKey: string;
      encryptedSk: string;
      chacha20NonceB64u: string;
      wrapKeySalt: string;
      usage: 'runtime-signing' | 'export-only';
    } | null = null;

    // 2) Key material:
    // - threshold-signer: derive client verifying share from PRF.first (default)
    // - threshold-signer + backupLocalKey: also derive encrypted local backup key material for export
    // - local-signer (legacy compatibility): derive encrypted local key material for account key usage
    if (requestedSignerModeStr === 'threshold-signer') {
      const derived = await webAuthnManager.deriveThresholdEd25519ClientVerifyingShareFromCredential({
        credential,
        nearAccountId,
      });
      if (!derived.success || !derived.clientVerifyingShareB64u) {
        throw new Error(derived.error || 'Failed to derive threshold client verifying share');
      }
      thresholdClientVerifyingShareB64u = derived.clientVerifyingShareB64u;

      if (deriveLocalBackupKey) {
        const localKeyResult = await webAuthnManager.deriveNearKeypairAndEncryptFromSerialized({
          credential,
          nearAccountId,
          options: { deviceNumber, persistToDb: false },
        });
        if (!localKeyResult.success || !localKeyResult.publicKey) {
          const reason = localKeyResult?.error || 'Failed to derive local backup keypair with PRF';
          throw new Error(reason);
        }
        const localPublicKey = ensureEd25519Prefix(String(localKeyResult.publicKey || '').trim());
        if (!localPublicKey) {
          throw new Error('Missing local backup public key after key derivation');
        }
        const encryptedSk = String(localKeyResult.encryptedSk || '').trim();
        const chacha20NonceB64u = String(localKeyResult.chacha20NonceB64u || '').trim();
        const wrapKeySalt = String(localKeyResult.wrapKeySalt || '').trim();
        if (!encryptedSk || !chacha20NonceB64u || !wrapKeySalt) {
          throw new Error('Missing encrypted local backup key material after key derivation');
        }
        localKeyMaterialForPersist = {
          publicKey: localPublicKey,
          encryptedSk,
          chacha20NonceB64u,
          wrapKeySalt,
          usage: 'export-only',
        };
      }
    } else {
      const nearKeyResult = await webAuthnManager.deriveNearKeypairAndEncryptFromSerialized({
        credential,
        nearAccountId,
        options: { deviceNumber, persistToDb: false },
      });
      if (!nearKeyResult.success || !nearKeyResult.publicKey) {
        const reason = nearKeyResult?.error || 'Failed to generate NEAR keypair with PRF';
        throw new Error(reason);
      }
      const localPublicKey = ensureEd25519Prefix(String(nearKeyResult.publicKey || '').trim());
      if (!localPublicKey) {
        throw new Error('Missing local signer public key after key derivation');
      }
      const encryptedSk = String(nearKeyResult.encryptedSk || '').trim();
      const chacha20NonceB64u = String(nearKeyResult.chacha20NonceB64u || '').trim();
      const wrapKeySalt = String(nearKeyResult.wrapKeySalt || '').trim();
      if (!encryptedSk || !chacha20NonceB64u || !wrapKeySalt) {
        throw new Error('Missing encrypted local key material after key derivation');
      }
      localKeyMaterialForPersist = {
        publicKey: localPublicKey,
        encryptedSk,
        chacha20NonceB64u,
        wrapKeySalt,
        usage: 'runtime-signing',
      };
      accountNearPublicKey = localPublicKey;
    }

    // Step 4-5: Create account and register using the relay (atomic)
    onEvent?.({
      step: 2,
      phase: RegistrationPhase.STEP_2_KEY_GENERATION,
      status: RegistrationStatus.SUCCESS,
      message: requestedSignerModeStr === 'threshold-signer'
        ? (
          deriveLocalBackupKey
            ? 'Derived threshold client share and local backup key from passkey'
            : 'Derived threshold client share from passkey'
        )
        : 'Wallet derived successfully from passkey',
      verified: true,
      nearAccountId: nearAccountId,
      nearPublicKey: accountNearPublicKey || null,
    });

    let accountAndRegistrationResult;
    const rpId = webAuthnManager.getRpId();
    if (!rpId) {
      throw new Error('Missing rpId for relay registration');
    }
    accountAndRegistrationResult = await createAccountAndRegisterWithRelayServer(
      context,
      nearAccountId,
      requestedSignerModeStr === 'threshold-signer'
        ? undefined
        : accountNearPublicKey || undefined,
      credential,
      rpId,
      authenticatorOptions,
      onEvent,
      {
        thresholdEd25519: thresholdClientVerifyingShareB64u
          ? { clientVerifyingShareB64u: thresholdClientVerifyingShareB64u }
          : undefined,
      },
    );

    if (!accountAndRegistrationResult.success) {
      throw new Error(accountAndRegistrationResult.error || 'Account creation and registration failed');
    }

    // Update registration state based on results
    registrationState.accountCreated = true;
    registrationState.contractRegistered = true;
    registrationState.contractTransactionId = accountAndRegistrationResult.transactionId || null;

    // Step 6: Post-commit verification: ensure on-chain access key matches expected public key
    onEvent?.({
      step: 6,
      phase: RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION,
      status: RegistrationStatus.PROGRESS,
      message: 'Verifying on-chain access key matches expected public key...'
    });

    const thresholdPublicKey = String(accountAndRegistrationResult?.thresholdEd25519?.publicKey || '').trim();
    const relayerKeyId = String(accountAndRegistrationResult?.thresholdEd25519?.relayerKeyId || '').trim();
    const relayerVerifyingShareB64u = String(accountAndRegistrationResult?.thresholdEd25519?.relayerVerifyingShareB64u || '').trim();
    const accountCreationPublicKey = requestedSignerModeStr === 'threshold-signer'
      ? thresholdPublicKey
      : String(accountNearPublicKey || '').trim();
    if (!accountCreationPublicKey) {
      throw new Error('Missing account public key after registration');
    }
    const expectedAccessKeys: string[] = [accountCreationPublicKey];

    const accessKeyVerified = await verifyAccountAccessKeysPresent(
      context.nearClient,
      nearAccountId,
      expectedAccessKeys,
      { attempts: 3, delayMs: 200, finality: 'optimistic' },
    );

    if (!accessKeyVerified) {
      console.warn('[Registration] Access key not yet visible after atomic registration; continuing optimistically');
      onEvent?.({
        step: 6,
        phase: RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION,
        status: RegistrationStatus.SUCCESS,
        message: 'Access key verification pending (optimistic); continuing...'
      });
    } else {
      onEvent?.({
        step: 6,
        phase: RegistrationPhase.STEP_6_ACCOUNT_VERIFICATION,
        status: RegistrationStatus.SUCCESS,
        message: 'Access key verified on-chain'
      });
    }

    // For threshold-signer registrations, the account is created directly with the threshold key.
    // Confirm threshold key availability and continue.
    if (requestedSignerModeStr === 'threshold-signer') {
      if (!thresholdPublicKey || !relayerKeyId || !thresholdClientVerifyingShareB64u || !relayerVerifyingShareB64u) {
        throw new Error('Threshold registration did not return required key material');
      }

      // Step 7: ensure threshold key is available on-chain.
      onEvent?.({
        step: 7,
        phase: RegistrationPhase.STEP_7_THRESHOLD_KEY_ENROLLMENT,
        status: RegistrationStatus.PROGRESS,
        message: 'Confirming threshold key…',
        thresholdPublicKey,
        relayerKeyId,
        deviceNumber,
      });

      const thresholdConfirmed =
        accessKeyVerified
        || await verifyAccountAccessKeysPresent(
          context.nearClient,
          String(nearAccountId),
          [thresholdPublicKey],
          { attempts: 10, delayMs: 250, finality: 'optimistic' },
        );
      if (!thresholdConfirmed) {
        console.warn('[Registration] Threshold key not yet visible after atomic registration; continuing optimistically');
      }

      onEvent?.({
        step: 7,
        phase: RegistrationPhase.STEP_7_THRESHOLD_KEY_ENROLLMENT,
        status: RegistrationStatus.SUCCESS,
        message: thresholdConfirmed ? 'Threshold key ready' : 'Threshold key verification pending (optimistic)',
        thresholdKeyReady: thresholdConfirmed,
        thresholdPublicKey,
        relayerKeyId,
        deviceNumber,
      });
    }

    // Step 8: Store user data + authenticator locally
    onEvent?.({
      step: 8,
      phase: RegistrationPhase.STEP_8_DATABASE_STORAGE,
      status: RegistrationStatus.PROGRESS,
      message: 'Storing passkey wallet metadata...'
    });

    const clientNearPublicKey = requestedSignerModeStr === 'threshold-signer'
      ? String(thresholdPublicKey || '').trim()
      : accountCreationPublicKey;

    await webAuthnManager.atomicStoreRegistrationData({
      nearAccountId,
      credential,
      publicKey: clientNearPublicKey,
    });

    // Mark database as stored for rollback tracking
    registrationState.databaseStored = true;

    if (localKeyMaterialForPersist) {
      await IndexedDBManager.storeNearLocalKeyMaterialV2({
        nearAccountId,
        deviceNumber,
        publicKey: localKeyMaterialForPersist.publicKey,
        encryptedSk: localKeyMaterialForPersist.encryptedSk,
        chacha20NonceB64u: localKeyMaterialForPersist.chacha20NonceB64u,
        wrapKeySalt: localKeyMaterialForPersist.wrapKeySalt,
        usage: localKeyMaterialForPersist.usage,
        timestamp: Date.now(),
      });
    }

    if (thresholdPublicKey && relayerKeyId && thresholdClientVerifyingShareB64u) {
      await IndexedDBManager.storeNearThresholdKeyMaterialV2({
        nearAccountId,
        deviceNumber,
        publicKey: thresholdPublicKey,
        relayerKeyId,
        clientShareDerivation: 'prf_first_v1',
        participants: buildThresholdEd25519Participants2pV1({
          clientParticipantId: accountAndRegistrationResult?.thresholdEd25519?.clientParticipantId,
          relayerParticipantId: accountAndRegistrationResult?.thresholdEd25519?.relayerParticipantId,
          relayerKeyId,
          relayerUrl: context.configs?.relayer?.url,
          clientVerifyingShareB64u: thresholdClientVerifyingShareB64u,
          relayerVerifyingShareB64u,
          clientShareDerivation: 'prf_first_v1',
        }),
        timestamp: Date.now(),
      });
    }

    onEvent?.({
      step: 8,
      phase: RegistrationPhase.STEP_8_DATABASE_STORAGE,
      status: RegistrationStatus.SUCCESS,
      message: 'Registration metadata stored successfully'
    });

    // Initialize current user for immediate use (best-effort).
    try {
      await webAuthnManager.initializeCurrentUser(nearAccountId, context.nearClient);
    } catch (initErr) {
      console.warn('Failed to initialize current user after registration:', initErr);
    }

    onEvent?.({
      step: 9,
      phase: RegistrationPhase.STEP_9_REGISTRATION_COMPLETE,
      status: RegistrationStatus.SUCCESS,
      message: 'Registration completed!'
    });

    const successResult = {
      success: true,
      nearAccountId: nearAccountId,
      clientNearPublicKey,
      transactionId: registrationState.contractTransactionId,
    };

    afterCall?.(true, successResult);
    return successResult;

  } catch (error: unknown) {
    const message = (error && typeof error === 'object' && 'message' in error)
      ? String((error as { message?: unknown }).message || '')
      : String(error || '');
    const stack = (error && typeof error === 'object' && 'stack' in error)
      ? String((error as { stack?: unknown }).stack || '')
      : '';
    console.error('Registration failed:', message, stack);

    // Perform rollback based on registration state
    await performRegistrationRollback(
      registrationState,
      nearAccountId,
      webAuthnManager,
      onEvent
    );

    // Use centralized error handling
    const errorMessage = getUserFriendlyErrorMessage(error, 'registration', nearAccountId);

    const errorObject = new Error(errorMessage);
    onError?.(errorObject);

    onEvent?.({
      step: 0,
      phase: RegistrationPhase.REGISTRATION_ERROR,
      status: RegistrationStatus.ERROR,
      message: errorMessage,
      error: errorMessage
    } as RegistrationSSEEvent);

    const result = { success: false, error: errorMessage };
    afterCall?.(false);
    return result;
  }
}

// Backward-compatible wrapper without explicit confirmationConfig override
export async function registerPasskey(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  options: RegistrationHooksOptions,
  authenticatorOptions: AuthenticatorOptions
): Promise<RegistrationResult> {
  return registerPasskeyInternal(context, nearAccountId, options, authenticatorOptions, undefined);
}

//////////////////////////////////////
// HELPER FUNCTIONS
//////////////////////////////////////

// NOTE: legacy bootstrap challenge generation has been removed (threshold-only stack).

/**
 * Validates registration inputs and throws errors if invalid
 * @param nearAccountId - NEAR account ID to validate
 * @param onEvent - Optional callback for registration progress events
 * @param onError - Optional callback for error handling
 */
const validateRegistrationInputs = async (
  context: {
    configs: TatchiConfigs,
    webAuthnManager: WebAuthnManager,
    nearClient: NearClient,
  },
  nearAccountId: AccountId,
  onEvent?: (event: RegistrationSSEEvent) => void,
  onError?: (error: Error) => void,
) => {

  onEvent?.({
    step: 1,
    phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
    status: RegistrationStatus.PROGRESS,
    message: 'Validating registration inputs...'
  } as RegistrationSSEEvent);

  // Validation
  if (!nearAccountId) {
    const error = new Error('NEAR account ID is required for registration.');
    onError?.(error);
    throw error;
  }
  // Validate the account ID format
  const validation = validateNearAccountId(nearAccountId);
  if (!validation.valid) {
    const error = new Error(`Invalid NEAR account ID: ${validation.error}`);
    onError?.(error);
    throw error;
  }
  if (!window.isSecureContext) {
    const error = new Error('Passkey operations require a secure context (HTTPS or localhost).');
    onError?.(error);
    throw error;
  }

  // Best-effort pre-check: avoid prompting for passkey creation if the account name
  // is already taken on-chain. Final enforcement still happens in the relay + chain.
  onEvent?.({
    step: 1,
    phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
    status: RegistrationStatus.PROGRESS,
    message: `Checking if ${nearAccountId} already exists...`
  } as RegistrationSSEEvent);

  const accountExists = await checkNearAccountExistsBestEffort(context.nearClient, String(nearAccountId));
  if (accountExists) {
    const error = new Error(`Account ${nearAccountId} already exists. Please log in instead.`);
    onError?.(error);
    throw error;
  }

  onEvent?.({
    step: 1,
    phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
    status: RegistrationStatus.PROGRESS,
    message: `Account format validated, preparing confirmation`
  } as RegistrationSSEEvent);
  return;
}

/**
 * Rollback registration data in case of errors
 */
async function performRegistrationRollback(
  registrationState: {
    accountCreated: boolean;
    contractRegistered: boolean;
    databaseStored: boolean;
    contractTransactionId: string | null;
  },
  nearAccountId: AccountId,
  webAuthnManager: WebAuthnManager,
  onEvent?: (event: RegistrationSSEEvent) => void
): Promise<void> {
  console.debug('Starting registration rollback...', registrationState);

  // Rollback in reverse order
  try {
    // 1. Rollback database storage
    if (registrationState.databaseStored) {
      console.debug('Rolling back database storage...');
      onEvent?.({
        step: 0,
        phase: RegistrationPhase.REGISTRATION_ERROR,
        status: RegistrationStatus.ERROR,
        message: 'Rolling back database storage...',
        error: 'Registration failed - rolling back database storage'
      } as RegistrationSSEEvent);

      await webAuthnManager.rollbackUserRegistration(nearAccountId);
      console.debug('Database rollback completed');
    }

    // 2. On-chain rollback
    // NOT POSSIBLE - account creation is an on-chain transaction and cannot be rolled back.
    if (registrationState.contractRegistered) {
      console.debug('Registration transaction cannot be rolled back (immutable blockchain state)');
      onEvent?.({
        step: 0,
        phase: RegistrationPhase.REGISTRATION_ERROR,
        status: RegistrationStatus.ERROR,
        message: `Registration transaction (tx: ${registrationState.contractTransactionId}) cannot be rolled back`,
        error: 'Registration failed - on-chain state is immutable'
      } as RegistrationSSEEvent);
    }
    console.debug('Registration rollback completed');

  } catch (rollbackError: unknown) {
    console.error('Rollback failed:', rollbackError);
    onEvent?.({
      step: 0,
      phase: RegistrationPhase.REGISTRATION_ERROR,
      status: RegistrationStatus.ERROR,
      message: `Rollback failed: ${
        (rollbackError && typeof rollbackError === 'object' && 'message' in rollbackError)
          ? String((rollbackError as { message?: unknown }).message || '')
          : String(rollbackError || '')
      }`,
      error: 'Both registration and rollback failed'
    } as RegistrationSSEEvent);
  }
}

async function verifyAccountAccessKeysPresent(
  nearClient: NearClient,
  nearAccountId: string,
  expectedPublicKeys: string[],
  opts?: { attempts?: number; delayMs?: number; finality?: 'optimistic' | 'final' },
): Promise<boolean> {
  const unique = Array.from(
    new Set(expectedPublicKeys.map((k) => ensureEd25519Prefix(k)).filter(Boolean)),
  );
  if (!unique.length) return false;

  const attempts = Math.max(1, Math.floor(opts?.attempts ?? 6));
  const delayMs = Math.max(50, Math.floor(opts?.delayMs ?? 750));
  const finality = opts?.finality ?? 'optimistic';

  for (let i = 0; i < attempts; i++) {
    try {
      const accessKeyList = await nearClient.viewAccessKeyList(
        nearAccountId,
        { finality } as any,
      );
      const keys = accessKeyList.keys.map((k) => ensureEd25519Prefix(k.public_key)).filter(Boolean);
      const allPresent = unique.every((expected) => keys.includes(expected));
      if (allPresent) return true;
    } catch {
      // tolerate transient view errors during propagation; retry
    }
    if (i < attempts - 1) {
      await new Promise((res) => setTimeout(res, delayMs));
    }
  }
  return false;
}

async function fetchNonceBlockHashForKey(
  nearClient: NearClient,
  nearAccountId: string,
  publicKey: string,
  opts?: { attempts?: number; delayMs?: number; finality?: 'optimistic' | 'final' },
): Promise<{ nextNonce: string; blockHash: string }> {
  const attempts = Math.max(1, Math.floor(opts?.attempts ?? 6));
  const delayMs = Math.max(50, Math.floor(opts?.delayMs ?? 250));
  const finality = opts?.finality ?? 'final';

  const pk = ensureEd25519Prefix(publicKey);
  if (!pk) throw new Error('Missing publicKey for tx context fetch');

  let lastErr: unknown = null;
  for (let i = 0; i < attempts; i++) {
    try {
      const [accessKey, block] = await Promise.all([
        nearClient.viewAccessKey(String(nearAccountId), pk),
        nearClient.viewBlock({ finality } as any),
      ]);
      const nextNonce = (BigInt(accessKey.nonce) + 1n).toString();
      const blockHash = String((block as any)?.header?.hash || '').trim();
      if (!blockHash) throw new Error('Missing block hash from RPC');
      return { nextNonce, blockHash };
    } catch (e: unknown) {
      lastErr = e;
    }
    if (i < attempts - 1) {
      await new Promise((res) => setTimeout(res, delayMs));
    }
  }
  throw new Error(`Failed to fetch nonce/blockHash for ${nearAccountId}: ${String((lastErr as any)?.message || lastErr || '')}`);
}
