import type { NearClient } from '../NearClient';
import { ensureEd25519Prefix, validateNearAccountId } from '../../../../shared/src/utils/validation';
import type {
  RegistrationHooksOptions,
  RegistrationSSEEvent,
} from '../types/sdkSentEvents';
import type { RegistrationResult, TatchiConfigs } from '../types/tatchi';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import { RegistrationPhase, RegistrationStatus } from '../types/sdkSentEvents';
import { ActionType, toActionArgsWasm, type TransactionInputWasm } from '../types/actions';
import { DEFAULT_WAIT_STATUS } from '../types/rpc';
import {
  createAccountAndRegisterWithRelayServer
} from './faucets/createAccountRelayServer';
import { PasskeyManagerContext } from './index';
import { WebAuthnManager } from '../WebAuthnManager';
import { IndexedDBManager } from '../IndexedDBManager';
import { type ConfirmationConfig, type SignerMode, mergeSignerMode } from '../types/signer-worker';
import type { WebAuthnRegistrationCredential } from '../types/webauthn';
import type { AccountId } from '../types/accountIds';
import { errorMessage, getUserFriendlyErrorMessage } from '../../../../shared/src/utils/errors';
import { buildThresholdEd25519Participants2pV1 } from '../../../../shared/src/threshold/participants';
import { checkNearAccountExistsBestEffort } from '../rpcCalls';
import { deriveNearKeypairFromPrfSecondB64u } from '../nearCrypto';
import { __isWalletIframeHostMode } from '../WalletIframe/host-mode';
// Registration forces a visible, clickable confirmation for cross‑origin safety

/**
 * Core registration function that handles passkey registration
 *
 * Legacy proof-derived flows have been removed from the lite threshold-signer stack. Registration is now:
 * 1) Collect a standard WebAuthn registration credential (passkey).
 * 2) If `threshold-signer` is requested: derive a deterministic threshold client verifying share from PRF.first.
 *    Otherwise: derive and store an encrypted local NEAR key (v3 vault) from PRF outputs.
 * 3) Create/register the account via the relayer (threshold-only accounts are created with the threshold public key).
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
    const transactionContext = registrationSession.transactionContext;

    onEvent?.({
      step: 1,
      phase: RegistrationPhase.STEP_1_WEBAUTHN_VERIFICATION,
      status: RegistrationStatus.SUCCESS,
      message: 'WebAuthn ceremony successful'
    });

    const baseSignerMode = webAuthnManager.getUserPreferences().getSignerMode();
    const requestedSignerMode = mergeSignerMode(baseSignerMode, options?.signerMode);
    const requestedSignerModeStr = requestedSignerMode.mode;

    const deviceNumber = 1;
    let nearPublicKey: string | null = null;
    let nearPrivateKeyForBootstrap: string | null = null;
    let thresholdClientVerifyingShareB64u: string | null = null;

    // 2) Key material:
    // - threshold-signer: derive client verifying share from PRF.first (no local signer key)
    // - local-signer: derive and persist encrypted local key material
    if (requestedSignerModeStr === 'threshold-signer') {
      // Option B bootstrap: derive a local/backup key from PRF.second.
      // The relay creates the account with this key, and then the client adds the threshold key.
      const prfSecondB64u = String(credential?.clientExtensionResults?.prf?.results?.second || '').trim();
      if (!prfSecondB64u) {
        throw new Error('Missing PRF.second output from registration credential (required for backup key)');
      }
      const backupKeypair = await deriveNearKeypairFromPrfSecondB64u({
        prfSecondB64u,
        nearAccountId: String(nearAccountId),
      });
      nearPublicKey = backupKeypair.publicKey;
      nearPrivateKeyForBootstrap = backupKeypair.privateKey;

      const derived = await webAuthnManager.deriveThresholdEd25519ClientVerifyingShareFromCredential({
        credential,
        nearAccountId,
      });
      if (!derived.success || !derived.clientVerifyingShareB64u) {
        throw new Error(derived.error || 'Failed to derive threshold client verifying share');
      }
      thresholdClientVerifyingShareB64u = derived.clientVerifyingShareB64u;
    } else {
      const nearKeyResult = await webAuthnManager.deriveNearKeypairAndEncryptFromSerialized({
        credential,
        nearAccountId,
        options: { deviceNumber },
      });
      if (!nearKeyResult.success || !nearKeyResult.publicKey) {
        const reason = nearKeyResult?.error || 'Failed to generate NEAR keypair with PRF';
        throw new Error(reason);
      }
      nearPublicKey = nearKeyResult.publicKey;
    }

    // Step 4-5: Create account and register using the relay (atomic)
    onEvent?.({
      step: 2,
      phase: RegistrationPhase.STEP_2_KEY_GENERATION,
      status: RegistrationStatus.SUCCESS,
      message: requestedSignerModeStr === 'threshold-signer'
        ? 'Derived threshold client share and backup key from passkey'
        : 'Wallet derived successfully from passkey',
      verified: true,
      nearAccountId: nearAccountId,
      nearPublicKey: nearPublicKey || null,
    });

    let accountAndRegistrationResult;
    const rpId = webAuthnManager.getRpId();
    if (!rpId) {
      throw new Error('Missing rpId for relay registration');
    }
    accountAndRegistrationResult = await createAccountAndRegisterWithRelayServer(
      context,
      nearAccountId,
      // Option B: threshold-signer supplies a backup/local key for account creation.
      // Option A compatibility (older clients) can omit it, but the SDK prefers Option B.
      nearPublicKey || undefined,
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
    const accountCreationPublicKey = String(nearPublicKey || '').trim();
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

    // For threshold-signer registrations (Option B): client adds the threshold key AFTER account creation
    // (account is created with the backup/local key derived from PRF.second).
    if (requestedSignerModeStr === 'threshold-signer') {
      const relayerVerifyingShareB64u = String(accountAndRegistrationResult?.thresholdEd25519?.relayerVerifyingShareB64u || '').trim();
      if (!thresholdPublicKey || !relayerKeyId || !thresholdClientVerifyingShareB64u || !relayerVerifyingShareB64u) {
        throw new Error('Threshold registration did not return required key material');
      }

      if (!nearPrivateKeyForBootstrap) {
        throw new Error('Missing backup key material required to add threshold key');
      }

      // Step 7: add threshold key on-chain (client-signed with backup/local key) and verify.
      onEvent?.({
        step: 7,
        phase: RegistrationPhase.STEP_7_THRESHOLD_KEY_ENROLLMENT,
        status: RegistrationStatus.PROGRESS,
        message: 'Adding threshold key…',
        thresholdPublicKey,
        relayerKeyId,
        deviceNumber,
      });

      const thresholdAlreadyPresent = await verifyAccountAccessKeysPresent(
        context.nearClient,
        String(nearAccountId),
        [thresholdPublicKey],
        { attempts: 1, delayMs: 0, finality: 'optimistic' },
      );

      if (!thresholdAlreadyPresent) {
        const txContext = await fetchNonceBlockHashForKey(
          context.nearClient,
          String(nearAccountId),
          accountCreationPublicKey,
          { attempts: 10, delayMs: 250, finality: 'final' },
        );

        const signed = await context.webAuthnManager.signTransactionWithKeyPair({
          nearPrivateKey: nearPrivateKeyForBootstrap,
          signerAccountId: String(nearAccountId),
          receiverId: String(nearAccountId),
          nonce: txContext.nextNonce,
          blockHash: txContext.blockHash,
          actions: [
            toActionArgsWasm({
              type: ActionType.AddKey,
              publicKey: thresholdPublicKey,
              accessKey: { permission: 'FullAccess' },
            }),
          ],
        });

        await context.nearClient.sendTransaction(signed.signedTransaction, DEFAULT_WAIT_STATUS.thresholdAddKey);
      }

      const thresholdConfirmed = await verifyAccountAccessKeysPresent(
        context.nearClient,
        String(nearAccountId),
        [accountCreationPublicKey, thresholdPublicKey],
        { attempts: 10, delayMs: 250, finality: 'optimistic' },
      );
      if (!thresholdConfirmed) {
        console.warn('[Registration] Threshold key not yet visible after AddKey; continuing optimistically');
      }

      await IndexedDBManager.nearKeysDB.storeKeyMaterial({
        kind: 'threshold_ed25519_2p_v1',
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

      onEvent?.({
        step: 7,
        phase: RegistrationPhase.STEP_7_THRESHOLD_KEY_ENROLLMENT,
        status: RegistrationStatus.SUCCESS,
        message: thresholdConfirmed ? 'Threshold key ready' : 'Threshold key submitted (awaiting on-chain propagation)',
        thresholdKeyReady: true,
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

    // Step 9 (best-effort): enable an escape-hatch key derived from PRF.second and add it on-chain.
    await enableNearEscapeHatchBackupKeyBestEffort({
      context,
      nearAccountId,
      registrationCredential: credential,
      signerMode: requestedSignerMode,
      confirmationConfigOverride: confirmationConfig,
      onEvent,
    });

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

async function enableNearEscapeHatchBackupKeyBestEffort(args: {
  context: PasskeyManagerContext;
  nearAccountId: AccountId;
  registrationCredential: WebAuthnRegistrationCredential;
  signerMode: SignerMode;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  onEvent?: (event: RegistrationSSEEvent) => void;
}): Promise<void> {
  const { context, nearAccountId, registrationCredential, signerMode, onEvent } = args;

  try {
    if (signerMode.mode !== 'threshold-signer') return;
    if (!__isWalletIframeHostMode()) return;

    const withTimeout = async <T,>(
      promise: Promise<T>,
      timeoutMs: number,
      onTimeout: () => void,
    ): Promise<T> => {
      if (timeoutMs <= 0) return await promise;
      return await new Promise<T>((resolve, reject) => {
        const timeoutId = setTimeout(() => {
          try {
            onTimeout();
          } finally {
            reject(new Error(`Timed out after ${timeoutMs}ms`));
          }
        }, timeoutMs);
        promise.then(
          (value) => {
            clearTimeout(timeoutId);
            resolve(value);
          },
          (error) => {
            clearTimeout(timeoutId);
            reject(error);
          },
        );
      });
    };

    const prfSecondB64u = String(registrationCredential?.clientExtensionResults?.prf?.results?.second || '').trim();
    if (!prfSecondB64u) {
      onEvent?.({
        step: 9,
        phase: RegistrationPhase.STEP_9_ESCAPE_HATCH,
        status: RegistrationStatus.SUCCESS,
        message: 'Backup key skipped (PRF.second unavailable)',
        error: 'Missing PRF.second output in registration credential',
      });
      return;
    }

    const { publicKey: backupPublicKey } = await deriveNearKeypairFromPrfSecondB64u({
      prfSecondB64u,
      nearAccountId: String(nearAccountId),
    });

    const alreadyPresent = await verifyAccountAccessKeysPresent(
      context.nearClient,
      String(nearAccountId),
      [backupPublicKey],
      // Registration can race NEAR RPC propagation. Retry a few times to avoid
      // false negatives that would otherwise trigger an extra (second) confirmation.
      { attempts: 6, delayMs: 250, finality: 'optimistic' },
    );
    if (alreadyPresent) {
      onEvent?.({
        step: 9,
        phase: RegistrationPhase.STEP_9_ESCAPE_HATCH,
        status: RegistrationStatus.SUCCESS,
        message: 'Backup key already enabled',
        backupPublicKey,
      });
      return;
    }

    onEvent?.({
      step: 9,
      phase: RegistrationPhase.STEP_9_ESCAPE_HATCH,
      status: RegistrationStatus.PROGRESS,
      message: 'Enabling backup key (escape hatch)…',
      backupPublicKey,
    });

    const txInputsWasm: TransactionInputWasm[] = [
      {
        receiverId: String(nearAccountId),
        actions: [
          toActionArgsWasm({
            type: ActionType.AddKey,
            publicKey: backupPublicKey,
            accessKey: { permission: 'FullAccess' },
          }),
        ],
      },
    ];

    const signPromise = context.webAuthnManager.signTransactionsWithActions({
      transactions: txInputsWasm,
      rpcCall: {
        contractId: context.configs.contractId,
        nearRpcUrl: context.configs.nearRpcUrl,
        nearAccountId: String(nearAccountId),
      },
      signerMode,
      confirmationConfigOverride: {
        ...(args.confirmationConfigOverride ?? {}),
        uiMode: 'modal',
        behavior: 'requireClick',
      },
      title: 'Enable backup key (escape hatch)',
      body: 'Adds a backup key to your NEAR account so you can leave MPC later.',
    });

    const signed = await withTimeout(signPromise, 180_000, () => {
      // Best-effort: ensure the confirmer can unwind (releases reserved nonces) rather than hanging registration.
      try {
        window.postMessage({ type: 'MODAL_TIMEOUT', payload: 'Backup key confirmation timed out; continuing…' }, '*');
      } catch {}
    }).catch(async (err) => {
      // Give the underlying flow a moment to settle after MODAL_TIMEOUT so nonce reservations are released.
      try {
        await Promise.race([
          signPromise.catch(() => undefined),
          new Promise((resolve) => setTimeout(resolve, 1500)),
        ]);
      } catch {}
      throw err;
    });

    for (const item of signed) {
      const signedTx = item?.signedTransaction;
      if (!signedTx) throw new Error('Missing signed transaction for escape hatch AddKey');
      await context.nearClient.sendTransaction(signedTx, DEFAULT_WAIT_STATUS.thresholdAddKey);
    }

    const confirmed = await verifyAccountAccessKeysPresent(
      context.nearClient,
      String(nearAccountId),
      [backupPublicKey],
      { attempts: 6, delayMs: 400, finality: 'optimistic' },
    );

    onEvent?.({
      step: 9,
      phase: RegistrationPhase.STEP_9_ESCAPE_HATCH,
      status: RegistrationStatus.SUCCESS,
      message: confirmed
        ? 'Backup key enabled (escape hatch ready)'
        : 'Backup key transaction submitted (awaiting on-chain propagation)',
      backupPublicKey,
    });
  } catch (err: unknown) {
    const msg = errorMessage(err) || 'Failed to enable backup key';
    console.warn('[Registration] Backup key setup failed (continuing without escape hatch):', err);
    onEvent?.({
      step: 9,
      phase: RegistrationPhase.STEP_9_ESCAPE_HATCH,
      status: RegistrationStatus.SUCCESS,
      message: `Backup key not enabled (continuing): ${msg}`,
      error: msg,
    });
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
