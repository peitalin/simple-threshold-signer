import type { PasskeyManagerContext } from './index';
import type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  StartDevice2LinkingFlowArgs,
} from '../types/linkDevice';
import { DeviceLinkingPhase, DeviceLinkingStatus } from '../types/sdkSentEvents';
import { toAccountId } from '../types/accountIds';
import { errorMessage } from '../../utils/errors';
import { IndexedDBManager } from '../IndexedDBManager';
import { createNearKeypair, ensureEd25519Prefix } from '../nearCrypto';
import { getLoginSession } from './login';
import { DEVICE_LINKING_CONFIG } from '../../config';
import { removePrfOutputGuard, normalizeRegistrationCredential } from '../WebAuthnManager/credentialsHelpers';
import { buildThresholdEd25519Participants2pV1 } from '../../threshold/participants';
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
    if (!relayerUrl) return null;
    const url = `${relayerUrl}/link-device/session/${encodeURIComponent(sessionId)}`;
    const resp = await fetch(url, { method: 'GET' });
    if (!resp.ok) return null;
    const json: any = await resp.json().catch(() => ({}));
    if (json?.ok !== true) return null;
    const claimedAccountId = String(json?.session?.accountId || '').trim();
    const claimedPublicKey = String(json?.session?.device2PublicKey || '').trim();
    if (claimedPublicKey && this.session?.nearPublicKey && claimedPublicKey !== this.session.nearPublicKey) {
      return null;
    }
    const deviceNumberRaw = json?.session?.deviceNumber;
    const deviceNumber = Number.isFinite(deviceNumberRaw) ? Math.floor(deviceNumberRaw) : undefined;
    return claimedAccountId ? { accountId: claimedAccountId, ...(deviceNumber ? { deviceNumber } : {}) } : null;
  }

  private async waitForClaimAndComplete(): Promise<void> {
    const pollMs = DEVICE_LINKING_CONFIG.TIMEOUTS.POLLING_INTERVAL_MS;
    let announced = false;

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
      try {
        const claimed = await this.fetchClaimedSessionFromRelay(session.sessionId);
        if (claimed?.accountId) {
          const accountId = toAccountId(claimed.accountId);
          const deviceNumber = Number.isFinite(claimed.deviceNumber) ? claimed.deviceNumber : session.deviceNumber;
          this.session = { ...session, accountId, ...(deviceNumber ? { deviceNumber } : {}), phase: DeviceLinkingPhase.STEP_5_ADDKEY_DETECTED };
          this.safeOnEvent({
            step: 5,
            phase: DeviceLinkingPhase.STEP_5_ADDKEY_DETECTED,
            status: DeviceLinkingStatus.PROGRESS,
            message: `Linked to ${String(accountId)}; finishing setup…`,
          });
          await this.completeLinking();
          return;
        }
      } catch {
        // ignore and keep polling
      }

      await sleep(pollMs);
    }
  }

  private async completeLinking(): Promise<void> {
    if (this.cancelled) return;
    const session = this.session;
    if (!session?.accountId) throw new Error('LinkDeviceFlow: missing accountId for completion');

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

    const credentialForRelay = removePrfOutputGuard(normalizeRegistrationCredential(credential));
    const prepareResp = await fetch(`${relayerUrl.replace(/\/$/, '')}/link-device/prepare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        account_id: String(nearAccountId),
        device_number: resolvedDeviceNumber,
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

    const localSignerEnabled = this.options?.localSignerEnabled !== false;
    let localPublicKey: string | null = null;
    if (localSignerEnabled) {
      const localKeyResult = await this.context.webAuthnManager.deriveNearKeypairAndEncryptFromSerialized({
        credential,
        nearAccountId: String(nearAccountId),
        options: { deviceNumber: resolvedDeviceNumber },
      });
      if (!localKeyResult.success || !localKeyResult.publicKey) {
        throw new Error(localKeyResult.error || 'Failed to derive local signer key');
      }
      localPublicKey = ensureEd25519Prefix(String(localKeyResult.publicKey || '').trim());
      if (!localPublicKey) throw new Error('Local signer public key is empty');
    }

    this.safeOnEvent({
      step: 6,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
      status: DeviceLinkingStatus.PROGRESS,
      message: 'Activating linked device keys on-chain…',
    });

    const ephemeralPublicKey = ensureEd25519Prefix(String(session.nearPublicKey || '').trim());
    if (!ephemeralPublicKey) throw new Error('LinkDeviceFlow: missing ephemeral public key');

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

    const txContext = await this.fetchNonceBlockHashForKey(nearAccountId, ephemeralPublicKey);
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

    await IndexedDBManager.nearKeysDB.storeKeyMaterial({
      kind: 'threshold_ed25519_2p_v1',
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

    // Store authenticator + user data locally using the threshold public key as the active signing key.
    await this.storeDeviceAuthenticator({ nearPublicKey: thresholdPublicKey, credential });

    // Best-effort: set active user state for immediate use.
    try { await this.context.webAuthnManager.setLastUser(nearAccountId, resolvedDeviceNumber); } catch {}
    try { await this.context.webAuthnManager.initializeCurrentUser(nearAccountId, this.context.nearClient); } catch {}
    try { await getLoginSession(this.context, nearAccountId); } catch {}

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

    // 1) Store authenticator (local cache).
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

    // 2) Store user data (also sets lastUser pointer).
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
