import type { PasskeyManagerContext } from './index';
import { EmailRecoveryPhase } from '../types/sdkSentEvents';
import { EmailRecoveryStatus } from '../types/sdkSentEvents';
import type { EmailRecoveryFlowOptions, PendingEmailRecovery } from '../types/emailRecovery';
import { generateEmailRecoveryRequestId } from '../types/emailRecovery';
import { removePrfOutputGuard, normalizeRegistrationCredential } from '../signing/webauthn/credentials/helpers';
import { toAccountId } from '../types/accountIds';
import { buildThresholdEd25519Participants2pV1 } from '../../../../shared/src/threshold/participants';
import { IndexedDBManager } from '../IndexedDBManager';
import { EmailRecoveryPendingStore } from '../../utils/emailRecovery';
import { errorMessage } from '../../../../shared/src/utils/errors';

/**
 * Minimal placeholder for the legacy email recovery flow.
 *
 * The threshold-only refactor keeps email recovery as a product feature, but the
 * implementation is being reworked to avoid legacy on-chain/WebAuthn-contract coupling.
 */
export class EmailRecoveryFlow {
  private context: PasskeyManagerContext;
  private options?: EmailRecoveryFlowOptions;
  private pending: PendingEmailRecovery | null = null;
  private phase: EmailRecoveryPhase = EmailRecoveryPhase.STEP_1_PREPARATION;
  private cancelled = false;
  private error?: Error;
  private pollingTimer: ReturnType<typeof setInterval> | null = null;

  constructor(context: PasskeyManagerContext, options?: EmailRecoveryFlowOptions) {
    this.context = context;
    this.options = options;
  }

  setOptions(options?: EmailRecoveryFlowOptions): void {
    this.options = options;
  }

  getState(): { phase: EmailRecoveryPhase; pending: PendingEmailRecovery | null; error: Error | undefined } {
    return { phase: this.phase, pending: this.pending, error: this.error };
  }

  private getPendingStore(): EmailRecoveryFlowOptions['pendingStore'] {
    return this.options?.pendingStore
      || new EmailRecoveryPendingStore({
        getPendingTtlMs: () => Number(this.context.configs?.relayer?.emailRecovery?.pendingTtlMs || 30 * 60_000),
      });
  }

  private emit(ev: any): void {
    try { this.options?.onEvent?.(ev); } catch {}
  }

  async buildMailtoUrl(args: { accountId: string; nearPublicKey?: string }): Promise<string> {
    const accountId = toAccountId(args.accountId);
    const nearPublicKey = String(args.nearPublicKey || this.pending?.nearPublicKey || '').trim();
    const requestId = String(this.pending?.requestId || '').trim();
    const mailtoAddress = String(this.context.configs?.relayer?.emailRecovery?.mailtoAddress || '').trim();
    if (!mailtoAddress) return 'mailto:';
    if (!nearPublicKey || !requestId) return `mailto:${mailtoAddress}`;

    const subject = `recover-${requestId} ${String(accountId)} ${nearPublicKey}`;
    const body = 'tee-encrypted';
    return `mailto:${mailtoAddress}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }

  async start(args: { accountId: string }): Promise<{ mailtoUrl: string; nearPublicKey: string }> {
    try {
      const nearAccountId = toAccountId(args.accountId);
      const relayerUrl = String(this.context.configs?.relayer?.url || '').trim();
      if (!relayerUrl) throw new Error('Missing relayer url (configs.relayer.url)');

      const rpId = this.context.webAuthnManager.getRpId();
      if (!rpId) throw new Error('Missing rpId for email recovery flow');

      this.cancelled = false;
      this.error = undefined;
      this.phase = EmailRecoveryPhase.STEP_1_PREPARATION;

      this.emit({
        step: 1,
        phase: EmailRecoveryPhase.STEP_1_PREPARATION,
        status: EmailRecoveryStatus.PROGRESS,
        message: 'Preparing email recovery...',
      });

      const requestId = generateEmailRecoveryRequestId();
      const initialDeviceNumber = 1;

      this.emit({
        step: 2,
        phase: EmailRecoveryPhase.STEP_2_TOUCH_ID_REGISTRATION,
        status: EmailRecoveryStatus.PROGRESS,
        message: 'Creating passkey for recovery...',
      });

      const registrationSession = await this.context.webAuthnManager.requestRegistrationCredentialConfirmation({
        nearAccountId: String(nearAccountId),
        deviceNumber: initialDeviceNumber,
        confirmerText: this.options?.confirmerText,
        confirmationConfigOverride: this.options?.confirmationConfig,
      });

      const credential = registrationSession.credential;
      const intentDigest = String((registrationSession as any)?.intentDigest || '');
      const deviceNumber = (() => {
        const parts = intentDigest.split(':');
        const last = parts[parts.length - 1];
        const n = Number(last);
        return Number.isFinite(n) && n >= 1 ? Math.floor(n) : initialDeviceNumber;
      })();

      const derived = await this.context.webAuthnManager.deriveThresholdEd25519ClientVerifyingShareFromCredential({
        credential,
        nearAccountId,
      });
      if (!derived.success || !derived.clientVerifyingShareB64u) {
        throw new Error(derived.error || 'Failed to derive threshold client verifying share');
      }

      const credentialForRelay = removePrfOutputGuard(normalizeRegistrationCredential(credential));
      const prepareResp = await fetch(`${relayerUrl}/email-recovery/prepare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          account_id: String(nearAccountId),
          request_id: requestId,
          device_number: deviceNumber,
          threshold_ed25519: { client_verifying_share_b64u: derived.clientVerifyingShareB64u },
          rp_id: rpId,
          webauthn_registration: credentialForRelay,
        }),
      });
      const prepareJson: any = await prepareResp.json().catch(() => ({}));
      if (!prepareResp.ok || !prepareJson?.ok) {
        throw new Error(prepareJson?.message || prepareJson?.error || `email-recovery/prepare failed (HTTP ${prepareResp.status})`);
      }

      const thresholdPublicKey = String(prepareJson?.thresholdEd25519?.publicKey || '').trim();
      const relayerKeyId = String(prepareJson?.thresholdEd25519?.relayerKeyId || '').trim();
      const relayerVerifyingShareB64u = String(prepareJson?.thresholdEd25519?.relayerVerifyingShareB64u || '').trim();
      if (!thresholdPublicKey || !relayerKeyId || !relayerVerifyingShareB64u) {
        throw new Error('email-recovery/prepare returned incomplete threshold key material');
      }

      // Store local passkey records first.
      const credentialId = String((credential as any).rawId || '').trim();
      const attestationObject = String((credential as any)?.response?.attestationObject || '').trim();
      if (!credentialId || !attestationObject) {
        throw new Error('Missing WebAuthn registration attestation in credential');
      }
      const credentialPublicKey = await this.context.webAuthnManager.extractCosePublicKey(attestationObject);
      await this.context.webAuthnManager.storeUserData({
        nearAccountId,
        deviceNumber,
        clientNearPublicKey: thresholdPublicKey,
        lastUpdated: Date.now(),
        passkeyCredential: {
          id: String((credential as any).id || credentialId),
          rawId: credentialId,
        },
        version: 2,
      });
      await this.context.webAuthnManager.storeAuthenticator({
        nearAccountId,
        credentialId,
        credentialPublicKey,
        transports: Array.isArray((credential as any)?.response?.transports) ? (credential as any).response.transports : [],
        name: `Passkey for ${String(nearAccountId)}`,
        registered: new Date().toISOString(),
        syncedAt: new Date().toISOString(),
        deviceNumber,
      });

      await IndexedDBManager.storeNearThresholdKeyMaterialV2({
        nearAccountId,
        deviceNumber,
        publicKey: thresholdPublicKey,
        relayerKeyId,
        clientShareDerivation: 'prf_first_v1',
        participants: buildThresholdEd25519Participants2pV1({
          clientParticipantId: prepareJson?.thresholdEd25519?.clientParticipantId,
          relayerParticipantId: prepareJson?.thresholdEd25519?.relayerParticipantId,
          relayerKeyId,
          relayerUrl,
          clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
          relayerVerifyingShareB64u,
          clientShareDerivation: 'prf_first_v1',
        }),
        timestamp: Date.now(),
      });

      this.pending = {
        accountId: nearAccountId,
        deviceNumber,
        requestId,
        nearPublicKey: thresholdPublicKey,
        credential,
        createdAt: Date.now(),
        status: 'awaiting-email',
      };
      await this.getPendingStore()?.set?.(this.pending as any);

      this.phase = EmailRecoveryPhase.STEP_3_AWAIT_EMAIL;
      this.emit({
        step: 3,
        phase: EmailRecoveryPhase.STEP_3_AWAIT_EMAIL,
        status: EmailRecoveryStatus.SUCCESS,
        message: 'Email recovery prepared; send the email to continue',
        requestId,
        nearPublicKey: thresholdPublicKey,
      });

      const mailtoUrl = await this.buildMailtoUrl({ accountId: String(nearAccountId), nearPublicKey: thresholdPublicKey });
      return { mailtoUrl, nearPublicKey: thresholdPublicKey };
    } catch (err: unknown) {
      const e = err instanceof Error ? err : new Error(String(err || 'Unknown error'));
      this.error = e;
      this.phase = EmailRecoveryPhase.ERROR;
      this.options?.onError?.(e);
      this.emit({
        step: 0,
        phase: EmailRecoveryPhase.ERROR,
        status: EmailRecoveryStatus.ERROR,
        message: 'Email recovery failed',
        error: e.message,
      });
      throw e;
    }
  }

  async startPolling(_args: { accountId: string; nearPublicKey?: string }): Promise<void> {
    if (this.pollingTimer) return;
    const pollEveryMs = Number(this.context.configs?.relayer?.emailRecovery?.pollingIntervalMs || 4000);
    const maxMs = Number(this.context.configs?.relayer?.emailRecovery?.maxPollingDurationMs || 30 * 60_000);
    const startedAt = Date.now();
    const targetAccountId = toAccountId(_args.accountId);
    const targetPk = String(_args.nearPublicKey || this.pending?.nearPublicKey || '').trim();
    if (!targetPk) return;

    this.phase = EmailRecoveryPhase.STEP_4_POLLING_ADD_KEY;
    this.emit({
      step: 4,
      phase: EmailRecoveryPhase.STEP_4_POLLING_ADD_KEY,
      status: EmailRecoveryStatus.PROGRESS,
      message: 'Polling for AddKey on-chain...',
    });

    const tick = async (): Promise<void> => {
      if (this.cancelled) return;
      if (Date.now() - startedAt > maxMs) {
        this.stopPolling();
        return;
      }
      try {
        const list = await this.context.nearClient.viewAccessKeyList(String(targetAccountId));
        const keys = Array.isArray((list as any)?.keys) ? (list as any).keys : [];
        const found = keys.some((k: any) => String(k?.public_key || '').trim() === targetPk);
        if (found) {
          this.phase = EmailRecoveryPhase.STEP_5_FINALIZING_REGISTRATION;
          this.emit({
            step: 5,
            phase: EmailRecoveryPhase.STEP_5_FINALIZING_REGISTRATION,
            status: EmailRecoveryStatus.SUCCESS,
            message: 'AddKey detected on-chain',
          });
          this.stopPolling();
        }
      } catch {
        // ignore transient RPC errors
      }
    };

    this.pollingTimer = setInterval(() => void tick(), Math.max(500, pollEveryMs));
    void tick();
  }

  stopPolling(): void {
    if (this.pollingTimer) {
      try { clearInterval(this.pollingTimer); } catch {}
    }
    this.pollingTimer = null;
  }

  async cancelAndReset(_args?: { accountId?: string; nearPublicKey?: string }): Promise<void> {
    this.cancelled = true;
    this.pending = null;
    this.phase = EmailRecoveryPhase.STEP_1_PREPARATION;
    this.error = undefined;
    this.stopPolling();
    try {
      const accountId = _args?.accountId ? toAccountId(_args.accountId) : null;
      if (accountId) {
        await this.getPendingStore()?.clear?.(accountId, _args?.nearPublicKey);
      }
    } catch { }
  }

  async finalize(_args: { accountId: string; nearPublicKey?: string }): Promise<void> {
    try {
      const accountId = toAccountId(_args.accountId);
      const pk = String(_args.nearPublicKey || '').trim();
      const store = this.getPendingStore();
      const pending = await store?.get?.(accountId, pk || undefined);
      const targetPk = String(pk || pending?.nearPublicKey || '').trim();
      if (!targetPk) {
        throw new Error('Missing nearPublicKey to finalize email recovery');
      }

      this.phase = EmailRecoveryPhase.STEP_4_POLLING_ADD_KEY;
      this.emit({
        step: 4,
        phase: EmailRecoveryPhase.STEP_4_POLLING_ADD_KEY,
        status: EmailRecoveryStatus.PROGRESS,
        message: 'Waiting for AddKey on-chain...',
      });

      const pollEveryMs = Number(this.context.configs?.relayer?.emailRecovery?.pollingIntervalMs || 4000);
      const maxMs = Number(this.context.configs?.relayer?.emailRecovery?.maxPollingDurationMs || 30 * 60_000);
      const startedAt = Date.now();
      let found = false;

      while (Date.now() - startedAt < maxMs) {
        if (this.cancelled) throw new Error('cancelled');
        const list = await this.context.nearClient.viewAccessKeyList(String(accountId));
        const keys = Array.isArray((list as any)?.keys) ? (list as any).keys : [];
        found = keys.some((k: any) => String(k?.public_key || '').trim() === targetPk);
        if (found) break;
        await new Promise((r) => setTimeout(r, Math.max(500, pollEveryMs)));
      }

      if (!found) {
        throw new Error('Timed out waiting for AddKey');
      }

      this.phase = EmailRecoveryPhase.STEP_6_COMPLETE;
      this.emit({
        step: 6,
        phase: EmailRecoveryPhase.STEP_6_COMPLETE,
        status: EmailRecoveryStatus.SUCCESS,
        message: 'Email recovery complete',
      });

      if (pending?.nearPublicKey) {
        await store?.clear?.(accountId, pending.nearPublicKey);
      }
      this.pending = null;
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Email recovery finalize failed';
      const err = e instanceof Error ? e : new Error(msg);
      this.error = err;
      this.phase = EmailRecoveryPhase.ERROR;
      this.options?.onError?.(err);
      this.emit({
        step: 0,
        phase: EmailRecoveryPhase.ERROR,
        status: EmailRecoveryStatus.ERROR,
        message: 'Email recovery finalize failed',
        error: msg,
      });
      throw err;
    }
  }
}
