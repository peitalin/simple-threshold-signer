import type { PasskeyManagerContext } from './index';
import type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  StartDevice2LinkingFlowArgs,
} from '../types/linkDevice';
import { DeviceLinkingPhase, DeviceLinkingStatus } from '../types/sdkSentEvents';
import { toAccountId } from '../types/accountIds';
import { errorMessage } from '../../../../shared/src/utils/errors';
import { IndexedDBManager } from '../IndexedDBManager';
import { createNearKeypair, ensureEd25519Prefix } from '../near/nearCrypto';
import { getLoginSession } from './login';
import { DEVICE_LINKING_CONFIG } from '../../config';
import { normalizeRegistrationCredential } from '../signing/webauthn/credentials/helpers';
import { redactCredentialExtensionOutputs } from '../signing/webauthn/credentials';
import { buildThresholdEd25519Participants2pV1 } from '../../../../shared/src/threshold/participants';
import { DEFAULT_WAIT_STATUS } from '../types/rpc';
import { ActionType, type ActionArgsWasm } from '../types/actions';

type DeterministicKeysResultLike = {
  nearPublicKey?: string;
  credential?: any;
};

function nowMs(): number {
  return Date.now();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function coerceDeviceNumber(input: unknown): number {
  const n = typeof input === 'number' ? input : Number(input);
  return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1;
}

function parseDeviceNumberFromIntentDigest(intentDigest: string, fallback: number): number {
  const raw = String(intentDigest || '').trim();
  if (!raw) return fallback;
  const parts = raw.split(':');
  if (parts.length < 2) return fallback;
  const n = Number(parts[parts.length - 1]);
  return Number.isFinite(n) && n >= 1 ? Math.floor(n) : fallback;
}


// Lazy-load QRCode to keep it an optional peer and reduce baseline bundle size.
async function generateQRCodeDataURL(data: string): Promise<string> {
  const mod: any = await import('qrcode');
  const QRCode = mod?.default ?? mod;
  if (typeof QRCode?.toDataURL !== 'function') {
    throw new Error('QRCode generation unavailable (missing qrcode.toDataURL)');
  }
  return await QRCode.toDataURL(data, {
    width: 256,
    margin: 2,
    color: { dark: '#000000', light: '#ffffff' },
    errorCorrectionLevel: 'M',
  });
}

/**
 * Device linking flow class.
 *
 * Note: The legacy linking flow is being refactored to the threshold-only stack.
 * This implementation currently keeps the local persistence guarantees used by regressions/tests
 * (store authenticator + user data so the account is immediately signable on the new device).
 */
export class LinkDeviceFlow {
  private context: PasskeyManagerContext;
  private options: StartDevice2LinkingFlowArgs;
  // Keep as a normal TS-private field (not #private) so existing runtime tests can patch it.
  private session: DeviceLinkingSession | null = null;
  private error?: Error;
  private cancelled = false;
  private completionInFlight: Promise<void> | null = null;

  constructor(context: PasskeyManagerContext, options: StartDevice2LinkingFlowArgs) {
    this.context = context;
    this.options = options;
  }

  private safeOnEvent(ev: any): void {
    try {
      this.options?.options?.onEvent?.(ev);
    } catch {
      // ignore
    }
  }

  private handleError(err: unknown): void {
    const e = err instanceof Error ? err : new Error(String(err || 'Unknown error'));
    this.error = e;
    this.session = this.session ? { ...this.session, phase: DeviceLinkingPhase.DEVICE_LINKING_ERROR } : null;
    this.safeOnEvent({
      step: 0,
      phase: DeviceLinkingPhase.DEVICE_LINKING_ERROR,
      status: DeviceLinkingStatus.ERROR,
      message: e.message,
      error: e.message,
    });
    try { this.options?.options?.onError?.(e); } catch {}
  }

  private async fetchClaimedSessionFromRelay(sessionId: string): Promise<{ accountId: string; deviceNumber?: number } | null> {
    const relayerUrl = String(this.context?.configs?.relayer?.url || '').trim().replace(/\/$/, '');
    if (!relayerUrl) {
      console.debug('[LinkDeviceFlow] relay polling skipped (missing relayer url)', { sessionId });
      return null;
    }
    const url = `${relayerUrl}/link-device/session/${encodeURIComponent(sessionId)}`;
    const resp = await fetch(url, { method: 'GET' });
    if (!resp.ok) {
      console.debug('[LinkDeviceFlow] relay poll response not ok', { sessionId, url, status: resp.status });
      return null;
    }
    const json: any = await resp.json().catch(() => ({}));
    if (json?.ok !== true) {
      console.debug('[LinkDeviceFlow] relay poll response not ok=true', { sessionId, url, json });
      return null;
    }
    const claimedAccountId = String(json?.session?.accountId || '').trim();
    const claimedPublicKey = String(json?.session?.device2PublicKey || '').trim();
    if (claimedPublicKey && this.session?.nearPublicKey && claimedPublicKey !== this.session.nearPublicKey) {
      console.debug('[LinkDeviceFlow] relay poll publicKey mismatch', {
        sessionId,
        url,
        claimedPublicKey,
        expectedPublicKey: this.session.nearPublicKey,
      });
      return null;
    }
    const deviceNumberRaw = json?.session?.deviceNumber;
    const deviceNumber = Number.isFinite(deviceNumberRaw) ? Math.floor(deviceNumberRaw) : undefined;
    console.debug('[LinkDeviceFlow] relay poll ok', {
      sessionId,
      url,
      claimed: !!claimedAccountId,
      ...(claimedAccountId ? { accountId: claimedAccountId } : {}),
      ...(deviceNumber ? { deviceNumber } : {}),
    });
    return claimedAccountId ? { accountId: claimedAccountId, ...(deviceNumber ? { deviceNumber } : {}) } : null;
  }

  private async registerSessionOnRelay(sessionId: string, device2PublicKey: string, expiresAtMs: number): Promise<void> {
    const relayerUrl = String(this.context?.configs?.relayer?.url || '').trim().replace(/\/$/, '');
    if (!relayerUrl) return;
    try {
      const resp = await fetch(`${relayerUrl}/link-device/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: sessionId,
          device2_public_key: device2PublicKey,
          expires_at_ms: expiresAtMs,
        }),
      });
      const json: any = await resp.json().catch(() => ({}));
      if (!resp.ok || json?.ok !== true) {
        console.warn('[link-device] session register failed:', json?.message || `HTTP ${resp.status}`);
      } else {
        console.debug('[LinkDeviceFlow] session registered on relay', { sessionId, device2PublicKey, expiresAtMs });
      }
    } catch (err) {
      console.warn('[link-device] session register error:', err);
    }
  }

  private async waitForClaimAndComplete(): Promise<void> {
    const pollMs = DEVICE_LINKING_CONFIG.TIMEOUTS.POLLING_INTERVAL_MS;
    let announced = false;
    let attempt = 0;

    while (!this.cancelled) {
      const session = this.session;
      if (!session?.sessionId) return;
      if (Date.now() > session.expiresAt) {
        throw new Error('Device linking session expired; regenerate the QR code and try again');
      }

      if (!announced) {
        announced = true;
        this.safeOnEvent({
          step: 4,
          phase: DeviceLinkingPhase.STEP_4_POLLING,
          status: DeviceLinkingStatus.PROGRESS,
          message: 'Waiting for Device1 to scan and authorize…',
        });
      }

      // Poll relay for a claimed session (Device1 posts accountId after AddKey).
      attempt++;
      if (attempt <= 3 || attempt % 10 === 0) {
        console.debug('[LinkDeviceFlow] polling relay for claim', {
          sessionId: session.sessionId,
          attempt,
          pollMs,
        });
      }
      let claimed: { accountId: string; deviceNumber?: number } | null = null;
      try {
        claimed = await this.fetchClaimedSessionFromRelay(session.sessionId);
      } catch (e) {
        console.debug('[LinkDeviceFlow] relay poll threw', { sessionId: session.sessionId, error: String((e as any)?.message || e) });
        claimed = null;
      }
      if (claimed?.accountId) {
        const accountId = toAccountId(claimed.accountId);
        const deviceNumber = Number.isFinite(claimed.deviceNumber) ? claimed.deviceNumber : session.deviceNumber;
        console.debug('[LinkDeviceFlow] claim detected; starting completion', {
          sessionId: session.sessionId,
          accountId: String(accountId),
          ...(deviceNumber ? { deviceNumber } : {}),
        });
        this.session = { ...session, accountId, ...(deviceNumber ? { deviceNumber } : {}), phase: DeviceLinkingPhase.STEP_5_ADDKEY_DETECTED };
        this.safeOnEvent({
          step: 5,
          phase: DeviceLinkingPhase.STEP_5_ADDKEY_DETECTED,
          status: DeviceLinkingStatus.PROGRESS,
          message: `Linked to ${String(accountId)}; finishing setup…`,
        });
        // Important: don't swallow completion errors; surface them to the caller so UI can show a failure.
        await this.completeLinking();
        console.debug('[LinkDeviceFlow] completion finished', { sessionId: session.sessionId, accountId: String(accountId) });
        return;
      }

      await sleep(pollMs);
    }
  }

  private async completeLinking(): Promise<void> {
    if (this.cancelled) return;
    const session = this.session;
    if (!session?.accountId) throw new Error('LinkDeviceFlow: missing accountId for completion');

    console.debug('[LinkDeviceFlow] completeLinking start', {
      sessionId: session.sessionId,
      accountId: String(session.accountId),
      deviceNumber: session.deviceNumber,
    });

    const nearAccountId = toAccountId(String(session.accountId));
    const relayerUrl = String(this.context?.configs?.relayer?.url || '').trim();
    if (!relayerUrl) throw new Error('Missing relayer url (configs.relayer.url)');
    if (!session.tempPrivateKey) {
      throw new Error('LinkDeviceFlow: missing temporary private key for completion');
    }

    const rpId = this.context.webAuthnManager.getRpId();
    if (!rpId) throw new Error('Missing rpId for link-device flow');

    const deviceNumberHint = coerceDeviceNumber(session.deviceNumber ?? this.options?.deviceNumber ?? 2);

    this.session = { ...session, accountId: nearAccountId, deviceNumber: deviceNumberHint, phase: DeviceLinkingPhase.STEP_6_REGISTRATION };
    this.safeOnEvent({
      step: 6,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
      status: DeviceLinkingStatus.PROGRESS,
      message: 'Creating passkey for linked device…',
    });

    const confirm = await this.context.webAuthnManager.requestRegistrationCredentialConfirmation({
      nearAccountId,
      deviceNumber: deviceNumberHint,
      confirmerText: this.options?.options?.confirmerText,
      confirmationConfigOverride: this.options?.options?.confirmationConfig,
    });
    if (!confirm?.confirmed || !confirm?.credential) {
      throw new Error(confirm?.error || 'User cancelled link-device registration');
    }
    const credential = confirm.credential;
    const resolvedDeviceNumber = parseDeviceNumberFromIntentDigest(confirm.intentDigest, deviceNumberHint);

    const derived = await this.context.webAuthnManager.deriveThresholdEd25519ClientVerifyingShareFromCredential({
      credential,
      nearAccountId,
    });
    if (!derived.success || !derived.clientVerifyingShareB64u) {
      throw new Error(derived.error || 'Failed to derive threshold client verifying share');
    }

    const localSignerEnabled = this.options?.localSignerEnabled !== false;
    let localPublicKey: string | null = null;
    let localKeyMaterialForPersist: {
      publicKey: string;
      encryptedSk: string;
      chacha20NonceB64u: string;
      wrapKeySalt: string;
    } | null = null;
    if (localSignerEnabled) {
      const localKeyResult = await this.context.webAuthnManager.deriveNearKeypairAndEncryptFromSerialized({
        credential,
        nearAccountId: String(nearAccountId),
        options: { deviceNumber: resolvedDeviceNumber, persistToDb: false },
      });
      if (!localKeyResult.success || !localKeyResult.publicKey) {
        throw new Error(localKeyResult.error || 'Failed to derive local signer key');
      }
      localPublicKey = ensureEd25519Prefix(String(localKeyResult.publicKey || '').trim());
      if (!localPublicKey) throw new Error('Local signer public key is empty');
      const encryptedSk = String(localKeyResult.encryptedSk || '').trim();
      const chacha20NonceB64u = String(localKeyResult.chacha20NonceB64u || '').trim();
      const wrapKeySalt = String(localKeyResult.wrapKeySalt || '').trim();
      if (!encryptedSk || !chacha20NonceB64u || !wrapKeySalt) {
        throw new Error('Missing encrypted local key material after key derivation');
      }
      localKeyMaterialForPersist = {
        publicKey: localPublicKey,
        encryptedSk,
        chacha20NonceB64u,
        wrapKeySalt,
      };
    }

    const credentialForRelay = redactCredentialExtensionOutputs(normalizeRegistrationCredential(credential));
    const prepareResp = await fetch(`${relayerUrl.replace(/\/$/, '')}/link-device/prepare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        account_id: String(nearAccountId),
        device_number: resolvedDeviceNumber,
        ...(localPublicKey ? { local_public_key: localPublicKey } : {}),
        threshold_ed25519: { client_verifying_share_b64u: derived.clientVerifyingShareB64u },
        rp_id: rpId,
        webauthn_registration: credentialForRelay,
      }),
    });
    const prepareJson: any = await prepareResp.json().catch(() => ({}));
    if (!prepareResp.ok || !prepareJson?.ok) {
      throw new Error(prepareJson?.message || prepareJson?.error || `link-device/prepare failed (HTTP ${prepareResp.status})`);
    }

    const thresholdPublicKey = ensureEd25519Prefix(String(prepareJson?.thresholdEd25519?.publicKey || '').trim());
    const relayerKeyId = String(prepareJson?.thresholdEd25519?.relayerKeyId || '').trim();
    const relayerVerifyingShareB64u = String(prepareJson?.thresholdEd25519?.relayerVerifyingShareB64u || '').trim();
    if (!thresholdPublicKey || !relayerKeyId || !relayerVerifyingShareB64u) {
      throw new Error('link-device/prepare returned incomplete threshold key material');
    }

    this.safeOnEvent({
      step: 6,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
      status: DeviceLinkingStatus.PROGRESS,
      message: 'Activating linked device keys on-chain…',
    });

    const ephemeralPublicKey = ensureEd25519Prefix(String(session.nearPublicKey || '').trim());
    if (!ephemeralPublicKey) throw new Error('LinkDeviceFlow: missing ephemeral public key');

    console.debug('[LinkDeviceFlow] completing on-chain key swap', {
      sessionId: session.sessionId,
      accountId: String(nearAccountId),
      ephemeralPublicKey,
      thresholdPublicKey,
      ...(localPublicKey ? { localPublicKey } : {}),
    });

    const actions: ActionArgsWasm[] = [
      {
        action_type: ActionType.AddKey,
        public_key: thresholdPublicKey,
        access_key: JSON.stringify({ nonce: 0, permission: { FullAccess: {} } }),
      },
      ...(localPublicKey
        ? [{
          action_type: ActionType.AddKey,
          public_key: localPublicKey,
          access_key: JSON.stringify({ nonce: 0, permission: { FullAccess: {} } }),
        } satisfies ActionArgsWasm]
        : []),
      {
        action_type: ActionType.DeleteKey,
        public_key: ephemeralPublicKey,
      },
    ];

    // The AddKey propagation can take a moment; retry longer than default to avoid flakiness.
    const txContext = await this.fetchNonceBlockHashForKey(nearAccountId, ephemeralPublicKey, {
      attempts: 24,
      delayMs: 500,
      finality: 'optimistic',
    });
    const signed = await this.context.webAuthnManager.signTransactionWithKeyPair({
      nearPrivateKey: session.tempPrivateKey,
      signerAccountId: String(nearAccountId),
      receiverId: String(nearAccountId),
      nonce: txContext.nextNonce,
      blockHash: txContext.blockHash,
      actions,
    });
    await this.context.nearClient.sendTransaction(signed.signedTransaction, DEFAULT_WAIT_STATUS.linkDeviceSwapKey);

    this.session = {
      ...session,
      accountId: nearAccountId,
      deviceNumber: resolvedDeviceNumber,
      credential,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
    };

    // Store authenticator + user data first to ensure profile/account mapping exists.
    await this.storeDeviceAuthenticator({ nearPublicKey: thresholdPublicKey, credential });

    if (localKeyMaterialForPersist) {
      await IndexedDBManager.storeNearLocalKeyMaterialV2({
        nearAccountId,
        deviceNumber: resolvedDeviceNumber,
        publicKey: localKeyMaterialForPersist.publicKey,
        encryptedSk: localKeyMaterialForPersist.encryptedSk,
        chacha20NonceB64u: localKeyMaterialForPersist.chacha20NonceB64u,
        wrapKeySalt: localKeyMaterialForPersist.wrapKeySalt,
        usage: 'runtime-signing',
        timestamp: Date.now(),
      });
    }

    await IndexedDBManager.storeNearThresholdKeyMaterialV2({
      nearAccountId,
      deviceNumber: resolvedDeviceNumber,
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

    // Auto-login: set last-user + warm login state so the device is immediately usable.
    await this.attemptAutoLogin({ accountId: nearAccountId, deviceNumber: resolvedDeviceNumber });

    if (this.session?.tempPrivateKey) {
      this.session.tempPrivateKey = '';
    }

    if (this.cancelled) return;
    this.session = this.session ? { ...this.session, phase: DeviceLinkingPhase.STEP_7_LINKING_COMPLETE } : null;
    this.safeOnEvent({
      step: 7,
      phase: DeviceLinkingPhase.STEP_7_LINKING_COMPLETE,
      status: DeviceLinkingStatus.SUCCESS,
      message: 'Device linking completed',
    });
  }

  /**
   * Device2: Attempt auto-login after successful device linking.
   *
   * Note: In the lite-signer refactor we no longer do SecureConfirm WebAuthn verification/unlocks here.
   * Auto-login is simply: set last-user pointer + initialize current user state for signing.
   */
  private async attemptAutoLogin(input: { accountId: string; deviceNumber: number }): Promise<void> {
    try {
      if (this.cancelled) return;
      const nearAccountId = toAccountId(String(input.accountId));
      const deviceNumber = coerceDeviceNumber(input.deviceNumber);

      console.debug('[LinkDeviceFlow] auto-login start', { accountId: String(nearAccountId), deviceNumber });
      this.safeOnEvent({
        step: 8,
        phase: DeviceLinkingPhase.STEP_8_AUTO_LOGIN,
        status: DeviceLinkingStatus.PROGRESS,
        message: 'Logging in…',
      });

      await this.context.webAuthnManager.setLastUser(nearAccountId, deviceNumber).catch(() => undefined);
      await this.context.webAuthnManager.updateLastLogin(nearAccountId).catch(() => undefined);
      await this.context.webAuthnManager.initializeCurrentUser(nearAccountId, this.context.nearClient);
      const { login } = await getLoginSession(this.context, nearAccountId);
      if (!login?.isLoggedIn) {
        throw new Error(`Auto-login did not mark ${String(nearAccountId)} as logged in`);
      }

      this.safeOnEvent({
        step: 8,
        phase: DeviceLinkingPhase.STEP_8_AUTO_LOGIN,
        status: DeviceLinkingStatus.SUCCESS,
        message: `Welcome ${String(nearAccountId)}`,
      });
      console.debug('[LinkDeviceFlow] auto-login complete', { accountId: String(nearAccountId), deviceNumber });
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Auto-login failed after device linking';
      console.warn('[LinkDeviceFlow] auto-login failed:', e);
      // Don't fail linking if auto-login fails; user can manually login.
      this.safeOnEvent({
        step: 0,
        phase: DeviceLinkingPhase.LOGIN_ERROR,
        status: DeviceLinkingStatus.ERROR,
        message: msg,
        error: msg,
      });
    }
  }

  private async fetchNonceBlockHashForKey(
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
          this.context.nearClient.viewAccessKey(String(nearAccountId), pk),
          this.context.nearClient.viewBlock({ finality } as any),
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
    throw new Error(
      `Failed to fetch nonce/blockHash for ${nearAccountId}: ${String((lastErr as any)?.message || lastErr || '')}`,
    );
  }

  /**
   * Device2: Generate a QR payload for device1 to scan.
   *
   * Flow:
   * - Generate an ephemeral NEAR keypair (no accountId required).
   * - Render QR code for Device1 to scan + AddKey on-chain.
   * - Poll relay for mapping { sessionId -> accountId } to finish linking.
   */
  async generateQR(): Promise<{ qrData: DeviceLinkingQRData; qrCodeDataURL: string }> {
    try {
      const sessionId =
        (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
          ? `ldsess-${crypto.randomUUID()}`
          : `ldsess-${Date.now()}-${Math.random().toString(16).slice(2)}`;

      const deviceNumber = coerceDeviceNumber(this.options?.deviceNumber ?? 2);
      const tempKeypair = await createNearKeypair();

      this.session = {
        sessionId,
        accountId: null,
        deviceNumber,
        nearPublicKey: tempKeypair.publicKey,
        credential: null,
        tempPrivateKey: tempKeypair.privateKey,
        phase: DeviceLinkingPhase.STEP_1_QR_CODE_GENERATED,
        createdAt: nowMs(),
        expiresAt: nowMs() + DEVICE_LINKING_CONFIG.TIMEOUTS.SESSION_EXPIRATION_MS,
      };

      await this.registerSessionOnRelay(sessionId, tempKeypair.publicKey, this.session.expiresAt);

      const qrData: DeviceLinkingQRData = {
        sessionId,
        device2PublicKey: tempKeypair.publicKey,
        timestamp: nowMs(),
        version: 'v3',
      };

      const qrCodeDataURL = await generateQRCodeDataURL(JSON.stringify(qrData));

      this.safeOnEvent({
        step: 1,
        phase: DeviceLinkingPhase.STEP_1_QR_CODE_GENERATED,
        status: DeviceLinkingStatus.SUCCESS,
        message: 'Device linking QR generated',
      });

      if (!this.cancelled) {
        this.completionInFlight = this.waitForClaimAndComplete().catch((e) => this.handleError(e));
      }

      return { qrData, qrCodeDataURL };
    } catch (err: unknown) {
      const e = err instanceof Error ? err : new Error(String(err || 'Unknown error'));
      this.handleError(e);
      throw e;
    }
  }

  /**
   * Store authenticator + user data for the linked device so the account is immediately usable.
   *
   * This method is intentionally private in TS, but must remain callable at runtime for
   * regression tests (see `linkDevice.immediateSign.test.ts`).
   */
  private async storeDeviceAuthenticator(deterministicKeysResult: DeterministicKeysResultLike): Promise<void> {
    if (!this.session) {
      throw new Error('LinkDeviceFlow: missing session (cannot store device authenticator)');
    }
    const accountIdRaw = (this.session as any).accountId;
    const deviceNumberRaw = (this.session as any).deviceNumber;
    const credential = (deterministicKeysResult as any)?.credential ?? (this.session as any)?.credential;
    const nearPublicKey = String((deterministicKeysResult as any)?.nearPublicKey ?? (this.session as any)?.nearPublicKey ?? '').trim();

    const nearAccountId = toAccountId(String(accountIdRaw || '').trim());
    const deviceNumber = coerceDeviceNumber(deviceNumberRaw);
    if (!credential) throw new Error('LinkDeviceFlow: missing credential');
    if (!nearPublicKey) throw new Error('LinkDeviceFlow: missing nearPublicKey');

    const credentialId = String(credential.rawId || credential.id || '').trim();
    const attestationObject = String(credential.response?.attestationObject || '').trim();
    if (!credentialId) throw new Error('LinkDeviceFlow: missing credential.rawId');
    if (!attestationObject) throw new Error('LinkDeviceFlow: missing credential.response.attestationObject');

    const credentialPublicKey = await this.context.webAuthnManager.extractCosePublicKey(attestationObject);

    // 1) Store user data first (also sets last-user/profile pointer).
    await this.context.webAuthnManager.storeUserData({
      nearAccountId,
      deviceNumber,
      clientNearPublicKey: nearPublicKey,
      lastUpdated: nowMs(),
      passkeyCredential: {
        id: String(credential.id || credentialId),
        rawId: credentialId,
      },
      version: 2,
    });

    // 2) Store authenticator once profile/account mapping exists.
    await this.context.webAuthnManager.storeAuthenticator({
      nearAccountId,
      credentialId,
      credentialPublicKey,
      transports: Array.isArray(credential.response?.transports) ? credential.response.transports : [],
      name: `Passkey for ${nearAccountId}`,
      registered: new Date().toISOString(),
      syncedAt: new Date().toISOString(),
      deviceNumber,
    });
  }

  getState(): { phase: DeviceLinkingPhase | undefined; session: DeviceLinkingSession | null; error: Error | undefined } {
    return {
      phase: this.session?.phase,
      session: this.session,
      error: this.error,
    };
  }

  cancel(): void {
    this.cancelled = true;
    this.session = this.session
      ? { ...this.session, phase: DeviceLinkingPhase.DEVICE_LINKING_ERROR }
      : null;
  }

  reset(): void {
    this.cancelled = false;
    this.error = undefined;
    this.session = null;
  }
}

export async function linkDeviceErrorResult(message: string, err?: unknown): Promise<never> {
  const msg = err ? `${message}: ${errorMessage(err) || 'unknown error'}` : message;
  throw new Error(msg);
}
