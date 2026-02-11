import { ClientAuthenticatorData } from '../../../IndexedDBManager';
import { base64UrlDecode } from '../../../../../../shared/src/utils/encoders';
import {
  serializeAuthenticationCredentialWithPRF,
  getPrfFirstSaltV1,
  getPrfSecondSaltV1,
} from '../credentials/helpers';
import {
  authenticatorsToAllowCredentials as mapAuthenticatorsToAllowCredentials,
  type WebAuthnAllowCredential,
} from '../credentials/collectAuthenticationCredentialForChallengeB64u';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential
} from '../../../types/webauthn';
import { executeWebAuthnWithParentFallbacksSafari } from '../fallbacks';
// Local rpId policy helpers (moved back from WebAuthnFallbacks)
function isRegistrableSuffix(host: string, cand: string): boolean {
  if (!host || !cand) return false;
  if (host === cand) return true;
  return host.endsWith('.' + cand);
}

function resolveRpId(override: string | undefined, host: string | undefined): string {
  const h = (host || '').toLowerCase();
  const ov = (override || '').toLowerCase();
  if (ov && h && isRegistrableSuffix(h, ov)) return ov;
  return h || ov || '';
}

function decodeChallengeB64u(challengeB64u: string): Uint8Array {
  const decoded = base64UrlDecode(String(challengeB64u || ''));
  if (decoded.length !== 32) {
    throw new Error(`Invalid WebAuthn challenge: expected 32 bytes, got ${decoded.length}`);
  }
  return decoded;
}

export interface RegisterCredentialsArgs {
  nearAccountId: string,    // NEAR account ID for PRF salts and keypair derivation (always base account)
  challengeB64u: string,
  deviceNumber?: number, // Optional device number for device-specific user ID (0, 1, 2, etc.)
}

export interface AuthenticateCredentialsForChallengeB64uArgs {
  nearAccountId: string;
  /**
   * Base64url-encoded 32-byte challenge.
   *
   * For lite threshold sessions, this should be `sessionPolicyDigest32`.
   */
  challengeB64u: string;
  /**
   * Optional allowlist of credential IDs (base64url) to restrict the prompt.
   * When omitted or empty, the browser may display an account chooser for any
   * credential available for this rpId.
   */
  allowCredentials?: AllowCredential[];
  /**
   * When true, include PRF.second in the serialized credential.
   * Use only for explicit recovery/export flows (higher-friction paths).
   */
  includeSecondPrfOutput?: boolean;
}

export type AllowCredential = WebAuthnAllowCredential;

export function authenticatorsToAllowCredentials(
  authenticators: ClientAuthenticatorData[]
): AllowCredential[] {
  return mapAuthenticatorsToAllowCredentials(authenticators);
}

/**
 * TouchIdPrompt prompts for touchID,
 * creates credentials,
 * manages WebAuthn touchID prompts,
 * and generates credentials, and PRF Outputs
 */
export class TouchIdPrompt {
  private rpIdOverride?: string;
  private safariGetWebauthnRegistrationFallback: boolean;
  // create() only: internal abort controller + cleanup hooks
  private abortController?: AbortController;
  private removePageAbortHandlers?: () => void;
  private removeExternalAbortListener?: () => void;

  constructor(rpIdOverride?: string, safariGetWebauthnRegistrationFallback = false) {
    this.rpIdOverride = rpIdOverride;
    this.safariGetWebauthnRegistrationFallback = safariGetWebauthnRegistrationFallback === true;
  }

  getRpId(): string {
    try {
      return resolveRpId(this.rpIdOverride, window?.location?.hostname);
    } catch {
      return this.rpIdOverride || '';
    }
  }

  // Utility helpers for cross‑origin fallback
  private static _inIframe(): boolean {
    try { return window.self !== window.top; } catch { return true; }
  }

  /**
   * Authenticate with a caller-provided 32-byte challenge (base64url string).
   *
   * This is the preferred entry point for WebAuthn-only flows where the challenge
   * is already a canonical digest (e.g. `sessionPolicyDigest32`).
   */
  async getAuthenticationCredentialsSerializedForChallengeB64u({
    nearAccountId,
    challengeB64u,
    allowCredentials = [],
    includeSecondPrfOutput = false,
  }: AuthenticateCredentialsForChallengeB64uArgs): Promise<WebAuthnAuthenticationCredential> {
    // New controller per get() call
    this.abortController = new AbortController();
    this.removePageAbortHandlers = TouchIdPrompt.attachPageAbortHandlers(this.abortController);
    const rpId = this.getRpId();

    const challengeBytes = decodeChallengeB64u(challengeB64u);

    const publicKey: PublicKeyCredentialRequestOptions = {
      challenge: challengeBytes as BufferSource,
      rpId,
      userVerification: 'preferred' as UserVerificationRequirement,
      timeout: 60000,
      extensions: {
        prf: {
          eval: {
            first: getPrfFirstSaltV1() as BufferSource,
            second: getPrfSecondSaltV1() as BufferSource,
          }
        }
      }
    };
    if (allowCredentials.length > 0) {
      publicKey.allowCredentials = allowCredentials.map((credential) => ({
        id: base64UrlDecode(credential.id) as BufferSource,
        type: 'public-key' as PublicKeyCredentialType,
        transports: credential.transports,
      }));
    }

    try {
      const credentialMaybe = (await executeWebAuthnWithParentFallbacksSafari('get', publicKey, {
        rpId,
        inIframe: TouchIdPrompt._inIframe(),
        timeoutMs: publicKey.timeout as number | undefined,
        permitGetBridgeOnAncestorError: this.safariGetWebauthnRegistrationFallback,
        abortSignal: this.abortController.signal,
      })) as unknown;

      // Support parent-bridge fallback returning an already-serialized credential
      if (isSerializedAuthenticationCredential(credentialMaybe)) {
        return credentialMaybe;
      }

      return serializeAuthenticationCredentialWithPRF({
        credential: credentialMaybe as PublicKeyCredential,
        firstPrfOutput: true,
        secondPrfOutput: includeSecondPrfOutput,
      });
    } finally {
      this.removePageAbortHandlers?.();
      this.removePageAbortHandlers = undefined;
      this.removeExternalAbortListener?.();
      this.removeExternalAbortListener = undefined;
      this.abortController = undefined;
    }
  }

  /**
   * Internal method for generating WebAuthn registration credentials with PRF output
   * @param nearAccountId - NEAR account ID for PRF salts and keypair derivation (always base account)
   * @param challenge - Random challenge bytes for the registration ceremony
   * @param deviceNumber - Device number for device-specific user ID.
   * @returns Credential with PRF output
   */
  async generateRegistrationCredentialsInternal({
    nearAccountId,
    challengeB64u,
    deviceNumber,
  }: RegisterCredentialsArgs): Promise<PublicKeyCredential> {
    // New controller per create() call
    this.abortController = new AbortController();
    this.removePageAbortHandlers = TouchIdPrompt.attachPageAbortHandlers(this.abortController);
    // Single source of truth for rpId: use getRpId().
    const rpId = this.getRpId();
    const publicKey: PublicKeyCredentialCreationOptions = {
      challenge: decodeChallengeB64u(challengeB64u) as BufferSource,
      rp: {
        name: 'WebAuthn Passkey',
        id: rpId
      },
      user: {
        id: new TextEncoder().encode(generateDeviceSpecificUserId(nearAccountId, deviceNumber)),
        name: generateDeviceSpecificUserId(nearAccountId, deviceNumber),
        displayName: generateUserFriendlyDisplayName(nearAccountId, deviceNumber)
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },
        { alg: -257, type: 'public-key' }
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred'
      },
      timeout: 60000,
      attestation: 'none',
      extensions: {
        prf: {
          eval: {
            // Fixed, versioned salts. Account-scoping happens at the HKDF derivation layer.
            first: getPrfFirstSaltV1() as BufferSource,
            second: getPrfSecondSaltV1() as BufferSource,
          }
        }
      },
    };
    try {
      const result = await executeWebAuthnWithParentFallbacksSafari('create', publicKey, {
        rpId,
        inIframe: TouchIdPrompt._inIframe(),
        timeoutMs: publicKey.timeout as number | undefined,
        // Pass AbortSignal through when supported; Safari bridge path may ignore it.
        abortSignal: this.abortController.signal,
      });
      return result as PublicKeyCredential;
    } finally {
      this.removePageAbortHandlers?.();
      this.removePageAbortHandlers = undefined;
      this.removeExternalAbortListener?.();
      this.removeExternalAbortListener = undefined;
      this.abortController = undefined;
    }
  }
}

// Type guard for already-serialized authentication credential
function isSerializedAuthenticationCredential(x: unknown): x is WebAuthnAuthenticationCredential {
  if (!x || typeof x !== 'object') return false;
  const obj = x as { response?: unknown };
  const resp = obj.response as { authenticatorData?: unknown } | undefined;
  return typeof resp?.authenticatorData === 'string';
}

/**
 * Generate device-specific user ID to prevent Chrome sync conflicts
 * Creates technical identifiers with full account context
 *
 * @param nearAccountId - The NEAR account ID (e.g., "serp120.w3a-v1.testnet")
 * @param deviceNumber - The device number (optional, undefined for device 1, 2 for device 2, etc.)
 * @returns Technical identifier:
 *   - Device 1: "serp120.web3-authn.testnet"
 *   - Device 2: "serp120.web3-authn.testnet (2)"
 *   - Device 3: "serp120.web3-authn.testnet (3)"
 */
export function generateDeviceSpecificUserId(nearAccountId: string, deviceNumber?: number): string {
  // If no device number provided or device number is 1, this is the first device
  if (deviceNumber === undefined || deviceNumber === 1) {
    return nearAccountId;
  }
  // For additional devices, add device number in parentheses
  return `${nearAccountId} (${deviceNumber})`;
}

/**
 * Generate user-friendly display name for passkey manager UI
 * Creates clean, intuitive names that users will see
 *
 * @param nearAccountId - The NEAR account ID (e.g., "serp120.w3a-v1.testnet")
 * @param deviceNumber - The device number (optional, undefined for device 1, 2 for device 2, etc.)
 * @returns User-friendly display name:
 *   - Device 1: "serp120"
 *   - Device 2: "serp120 (device 2)"
 *   - Device 3: "serp120 (device 3)"
 */
function generateUserFriendlyDisplayName(nearAccountId: string, deviceNumber?: number): string {
  // Extract the base username (everything before the first dot)
  const baseUsername = nearAccountId.split('.')[0];
  // If no device number provided or device number is 1, this is the first device
  if (deviceNumber === undefined || deviceNumber === 1) {
    return baseUsername;
  }
  // For additional devices, add device number with friendly label
  return `${baseUsername} (device ${deviceNumber})`;
}

// Abort native WebAuthn when page is being hidden or unloaded
// Centralized here to keep WebAuthn lifecycle concerns alongside native calls.
export namespace TouchIdPrompt {
  export function attachPageAbortHandlers(controller: AbortController): () => void {
    const onVisibility = () => { if (document.hidden) controller.abort(); };
    const onPageHide = () => { controller.abort(); };
    const onBeforeUnload = () => { controller.abort(); };
    document.addEventListener('visibilitychange', onVisibility, { passive: true });
    window.addEventListener('pagehide', onPageHide, { passive: true });
    window.addEventListener('beforeunload', onBeforeUnload, { passive: true });
    return () => {
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('pagehide', onPageHide);
      window.removeEventListener('beforeunload', onBeforeUnload);
    };
  }
}
