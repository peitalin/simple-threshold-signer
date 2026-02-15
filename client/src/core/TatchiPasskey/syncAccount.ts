import type { SyncAccountHooksOptions } from '../types/sdkSentEvents';
import { SyncAccountPhase, SyncAccountStatus } from '../types/sdkSentEvents';
import type { PasskeyManagerContext } from './index';
import type { AccountId, WebAuthnAuthenticationCredential } from '../types';
import { toAccountId } from '../types/accountIds';
import { redactCredentialExtensionOutputs } from '../signing/webauthn/credentials';
import { base64UrlDecode } from '../../../../shared/src/utils/base64';
import { errorMessage } from '../../../../shared/src/utils/errors';
import { IndexedDBManager } from '../IndexedDBManager';
import { buildThresholdEd25519Participants2pV1 } from '../../../../shared/src/threshold/participants';

export interface SyncAccountResult {
  success: boolean;
  accountId: string;
  publicKey: string;
  message: string;
  error?: string;
  loginState?: {
    isLoggedIn: boolean;
  };
}

export interface PasskeyOptionWithoutCredential {
  credentialId: string;
  accountId: string | null;
  publicKey: string;
  displayName: string;
}

export interface PasskeySelection {
  credentialId: string;
  accountId: string | null;
}

/**
 * Minimal placeholder for the legacy syncAccount flow.
 *
 * The threshold-only refactor will re-implement account sync against relay-private authenticator
 * storage (not the legacy on-chain registry).
 */
export class SyncAccountFlow {
  private context: PasskeyManagerContext;
  private options?: SyncAccountHooksOptions;
  private phase: 'idle' | 'discovering' | 'ready' | 'syncing' | 'complete' | 'error' = 'idle';
  private error?: Error;
  private availableAccounts?: Array<{
    credentialId: string;
    accountId: AccountId | null;
    publicKey: string;
    displayName: string;
  }>;

  constructor(context: PasskeyManagerContext, options?: SyncAccountHooksOptions) {
    this.context = context;
    this.options = options;
  }

  async discover(_accountId?: string): Promise<PasskeyOptionWithoutCredential[]> {
    this.phase = 'discovering';
    this.error = undefined;
    this.availableAccounts = [];
    this.phase = 'ready';
    return [];
  }

  async sync(_selection: PasskeySelection): Promise<SyncAccountResult> {
    this.phase = 'syncing';
    this.error = undefined;
    try {
      const result = await syncAccount(this.context, _selection.accountId ? toAccountId(_selection.accountId) : null, this.options);
      this.phase = result.success ? 'complete' : 'error';
      return result;
    } catch (e: unknown) {
      const err = e instanceof Error ? e : new Error(String(e || 'Unknown error'));
      this.error = err;
      this.phase = 'error';
      return {
        success: false,
        accountId: _selection.accountId || '',
        publicKey: '',
        message: err.message,
        error: err.message,
        loginState: { isLoggedIn: false },
      };
    }
  }

  getState(): {
    phase: 'idle' | 'discovering' | 'ready' | 'syncing' | 'complete' | 'error';
    availableAccounts: Array<{ credentialId: string; accountId: AccountId | null; publicKey: string; displayName: string }> | undefined;
    error: Error | undefined;
    isReady: boolean;
    isComplete: boolean;
    hasError: boolean;
  } {
    return {
      phase: this.phase,
      availableAccounts: this.availableAccounts,
      error: this.error,
      isReady: this.phase === 'ready',
      isComplete: this.phase === 'complete',
      hasError: this.phase === 'error',
    };
  }

  reset(): void {
    this.phase = 'idle';
    this.error = undefined;
    this.availableAccounts = undefined;
  }
}

export async function syncAccount(
  context: PasskeyManagerContext,
  accountId: AccountId | null,
  options?: SyncAccountHooksOptions,
  reuseCredential?: WebAuthnAuthenticationCredential,
  allowedCredentialIds?: string[],
): Promise<SyncAccountResult> {
  const onEvent = options?.onEvent;

  const relayerUrl = String(context.configs.relayer?.url || '').trim();
  if (!relayerUrl) {
    return {
      success: false,
      accountId: accountId ? String(accountId) : '',
      publicKey: '',
      message: 'Missing relayer url (configs.relayer.url)',
      error: 'missing_relayer_url',
      loginState: { isLoggedIn: false },
    };
  }

  const rpId = context.webAuthnManager.getRpId();
  if (!rpId) {
    return {
      success: false,
      accountId: accountId ? String(accountId) : '',
      publicKey: '',
      message: 'Missing rpId for WebAuthn sync',
      error: 'missing_rp_id',
      loginState: { isLoggedIn: false },
    };
  }

  try {
    onEvent?.({
      step: 1,
      phase: SyncAccountPhase.STEP_1_PREPARATION,
      status: SyncAccountStatus.PROGRESS,
      message: 'Preparing account sync...',
    } as any);

    // 1) Get a relay-minted challenge for discovery.
    const optionsResp = await fetch(`${relayerUrl}/sync-account/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rp_id: rpId }),
    });
    const optionsJson: any = await optionsResp.json().catch(() => ({}));
    if (!optionsResp.ok || !optionsJson?.ok) {
      throw new Error(optionsJson?.message || optionsJson?.error || `sync-account/options failed (HTTP ${optionsResp.status})`);
    }

    const challengeId = String(optionsJson.challengeId || '').trim();
    const challengeB64u = String(optionsJson.challengeB64u || '').trim();
    if (!challengeId || !challengeB64u) {
      throw new Error('sync-account/options returned invalid challenge');
    }

    onEvent?.({
      step: 2,
      phase: SyncAccountPhase.STEP_2_WEBAUTHN_AUTHENTICATION,
      status: SyncAccountStatus.PROGRESS,
      message: 'Authenticating with passkey...',
    } as any);

    const allowCredentials = Array.isArray(allowedCredentialIds) && allowedCredentialIds.length
      ? allowedCredentialIds.map((id) => ({ id, transports: [] as string[] }))
      : [];

    // NOTE: We intentionally avoid requiring a known accountId for discovery. When `allowCredentials`
    // is empty, the browser prompts the user to select any passkey for `rpId`.
    const credential = reuseCredential || await context.webAuthnManager.getAuthenticationCredentialsSerialized({
      nearAccountId: (accountId || ('dummy.testnet' as any)) as any,
      challengeB64u,
      allowCredentials,
      includeSecondPrfOutput: false,
    } as any);

    const credentialForRelay = redactCredentialExtensionOutputs<WebAuthnAuthenticationCredential>(credential as any);
    const verifyResp = await fetch(`${relayerUrl}/sync-account/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId,
        webauthn_authentication: credentialForRelay,
      }),
    });
    const verifyJson: any = await verifyResp.json().catch(() => ({}));
    if (!verifyResp.ok || !verifyJson?.ok || !verifyJson?.verified) {
      throw new Error(verifyJson?.message || verifyJson?.error || `sync-account/verify failed (HTTP ${verifyResp.status})`);
    }

    const syncedAccountId = String(verifyJson.accountId || '').trim();
    if (!syncedAccountId) {
      throw new Error('sync-account/verify returned missing accountId');
    }
    if (accountId && String(accountId) !== syncedAccountId) {
      throw new Error(`Selected passkey is not registered for account ${String(accountId)}`);
    }

    const deviceNumber = (() => {
      const n = Number(verifyJson.deviceNumber);
      return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1;
    })();
    const publicKey = String(verifyJson.publicKey || '').trim();
    if (!publicKey) {
      throw new Error('sync-account/verify returned missing publicKey');
    }

    const credentialPublicKeyB64u = String(verifyJson.credentialPublicKeyB64u || '').trim();
    if (!credentialPublicKeyB64u) {
      throw new Error('sync-account/verify returned missing credentialPublicKeyB64u');
    }
    const credentialPublicKey = base64UrlDecode(credentialPublicKeyB64u);

    // 2) Persist user + authenticator data locally.
    const normalizedAccountId = toAccountId(syncedAccountId);
    await context.webAuthnManager.storeUserData({
      nearAccountId: normalizedAccountId,
      deviceNumber,
      clientNearPublicKey: publicKey,
      lastUpdated: Date.now(),
      passkeyCredential: {
        id: String((credential as any).id || ''),
        rawId: String((credential as any).rawId || ''),
      },
      version: 2,
    });
    await context.webAuthnManager.storeAuthenticator({
      nearAccountId: normalizedAccountId,
      credentialId: String((credential as any).rawId || ''),
      credentialPublicKey,
      transports: [],
      name: `Passkey for ${syncedAccountId}`,
      registered: new Date().toISOString(),
      syncedAt: new Date().toISOString(),
      deviceNumber,
    });

    onEvent?.({
      step: 4,
      phase: SyncAccountPhase.STEP_4_AUTHENTICATOR_SAVED,
      status: SyncAccountStatus.SUCCESS,
      message: 'Passkey saved locally',
    } as any);

    // 3) Persist threshold key material when available.
    const thresholdEd25519 = verifyJson.thresholdEd25519 || null;
    const relayerKeyId = String((thresholdEd25519?.relayerKeyId ?? verifyJson.relayerKeyId ?? '') || '').trim();
    if (relayerKeyId) {
      const relayerVerifyingShareB64u = String(thresholdEd25519?.relayerVerifyingShareB64u || '').trim();
      const derived = await context.webAuthnManager.deriveThresholdEd25519ClientVerifyingShareFromCredential({
        credential: credential as any,
        nearAccountId: normalizedAccountId,
      });
      const clientVerifyingShareB64u = derived.success ? String(derived.clientVerifyingShareB64u || '').trim() : '';

      await IndexedDBManager.storeNearThresholdKeyMaterialV2({
        nearAccountId: normalizedAccountId,
        deviceNumber,
        publicKey,
        relayerKeyId,
        clientShareDerivation: 'prf_first_v1',
        participants: buildThresholdEd25519Participants2pV1({
          clientParticipantId: thresholdEd25519?.clientParticipantId,
          relayerParticipantId: thresholdEd25519?.relayerParticipantId,
          relayerKeyId,
          relayerUrl: context.configs?.relayer?.url,
          clientVerifyingShareB64u,
          relayerVerifyingShareB64u,
          clientShareDerivation: 'prf_first_v1',
        }),
        timestamp: Date.now(),
      });
    }

    onEvent?.({
      step: 5,
      phase: SyncAccountPhase.STEP_5_SYNC_ACCOUNT_COMPLETE,
      status: SyncAccountStatus.SUCCESS,
      message: 'Account synced',
    } as any);

    return {
      success: true,
      accountId: syncedAccountId,
      publicKey,
      message: 'Account synced successfully',
      loginState: { isLoggedIn: false },
    };
  } catch (e: unknown) {
    const msg = errorMessage(e) || 'syncAccount failed';
    onEvent?.({
      step: 0,
      phase: SyncAccountPhase.ERROR,
      status: SyncAccountStatus.ERROR,
      message: 'Account sync failed',
      error: msg,
    } as any);
    return {
      success: false,
      accountId: accountId ? String(accountId) : '',
      publicKey: '',
      message: msg,
      error: msg,
      loginState: { isLoggedIn: false },
    };
  }
}
