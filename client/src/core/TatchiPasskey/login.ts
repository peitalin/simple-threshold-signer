import type {
  AfterCall,
  LoginHooksOptions,
  LoginSSEvent,
} from '../types/sdkSentEvents';
import { LoginPhase, LoginStatus } from '../types/sdkSentEvents';
import type {
  GetRecentLoginsResult,
  LoginAndCreateSessionResult,
  LoginResult,
  LoginSession,
  LoginState,
} from '../types/tatchi';
import type { PasskeyManagerContext } from './index';
import type { AccountId } from '../types/accountIds';
import { getUserFriendlyErrorMessage } from '../../../../shared/src/utils/errors';
import { authenticatorsToAllowCredentials } from '../signing/webauthn/credentials';
import { IndexedDBManager } from '../IndexedDBManager';
import type { ClientAuthenticatorData, ClientUserData } from '../IndexedDBManager';
import { createWebAuthnLoginOptions, verifyWebAuthnLogin } from '../near/rpcCalls';
import { parseDeviceNumber } from '../signing/webauthn/device/getDeviceNumber';
import { clearAllCachedThresholdEd25519AuthSessions } from '../signing/threshold/session/thresholdEd25519AuthSession';
import { normalizeThresholdEd25519ParticipantIds } from '../../../../shared/src/threshold/participants';

/**
 * Core login function (standard WebAuthn; relay-issued sessions).
 *
 * Responsibilities:
 * - Select the active account + passkey deviceNumber (last-user pointer).
 * - Optionally mint a relayer session (JWT/cookie) via standard WebAuthn challenge/verify.
 *
 * Note: signing flows still perform their own SecureConfirm/WebAuthn prompting as needed.
 */
export async function loginAndCreateSession(
  context: PasskeyManagerContext,
  nearAccountId: AccountId,
  options?: LoginHooksOptions
): Promise<LoginAndCreateSessionResult> {
  const { onEvent, onError, afterCall } = options || {};
  const { webAuthnManager } = context;

  onEvent?.({
    step: 1,
    phase: LoginPhase.STEP_1_PREPARATION,
    status: LoginStatus.PROGRESS,
    message: `Starting login for ${nearAccountId}`,
  });

  try {
    if (typeof window !== 'undefined' && !window.isSecureContext) {
      const errorMessage = 'Passkey operations require a secure context (HTTPS or localhost).';
      return await finalizeLoginError({
        message: errorMessage,
        error: new Error(errorMessage),
        onEvent,
        onError,
        afterCall,
        callAfterCall: false,
      });
    }

    const deviceNumberHint = parseDeviceNumber(options?.deviceNumber, { min: 1 });

    const hintUserPromise: Promise<ClientUserData | null> =
      deviceNumberHint !== null
        ? webAuthnManager.getUserByDevice(nearAccountId, deviceNumberHint).catch(() => null)
        : Promise.resolve(null);

    const [hintUser, lastUser, latestByAccount, authenticators] = await Promise.all([
      hintUserPromise,
      webAuthnManager.getLastUser().catch(() => null),
      IndexedDBManager.clientDB.getMostRecentNearAccountProjection(nearAccountId).catch(() => null),
      webAuthnManager.getAuthenticatorsByUser(nearAccountId).catch(() => []),
    ]);

    if (authenticators.length === 0) {
      throw new Error(`No authenticators found for account ${nearAccountId}. Please register an account.`);
    }

    let userData: ClientUserData | null = null;
    if (hintUser && hintUser.nearAccountId === nearAccountId) {
      userData = hintUser;
    } else if (latestByAccount && latestByAccount.nearAccountId === nearAccountId) {
      userData = latestByAccount;
    } else if (lastUser && lastUser.nearAccountId === nearAccountId) {
      userData = lastUser;
    } else {
      userData = await webAuthnManager.getUserByDevice(nearAccountId, 1).catch(() => null);
    }

    if (!userData) {
      throw new Error(`User data not found for ${nearAccountId} in IndexedDB. Please register an account.`);
    }
    if (!userData.clientNearPublicKey) {
      throw new Error(`No NEAR public key found for ${nearAccountId}. Please register an account.`);
    }

    const baseDeviceNumber =
      deviceNumberHint ??
      (Number.isFinite(userData.deviceNumber) && userData.deviceNumber >= 1 ? userData.deviceNumber : 1);

    const signingSessionPolicy = (() => {
      const ttlMsRaw = options?.signingSession?.ttlMs ?? context.configs?.signingSessionDefaults?.ttlMs;
      const remainingUsesRaw = options?.signingSession?.remainingUses ?? context.configs?.signingSessionDefaults?.remainingUses;
      const ttlMs = typeof ttlMsRaw === 'number' ? Math.floor(ttlMsRaw) : Math.floor(Number(ttlMsRaw) || 0);
      const remainingUses = typeof remainingUsesRaw === 'number'
        ? Math.floor(remainingUsesRaw)
        : Math.floor(Number(remainingUsesRaw) || 0);
      return {
        ttlMs: Math.max(0, ttlMs),
        remainingUses: Math.max(0, remainingUses),
      };
    })();

    let signingSession: LoginAndCreateSessionResult['signingSession'] | undefined;

    const maybeWarmThresholdSigningSession = async (deviceNumber: number): Promise<void> => {
      try {
        if (context.configs?.signerMode?.mode !== 'threshold-signer') return;
        if (!signingSessionPolicy.ttlMs || !signingSessionPolicy.remainingUses) return;

        const thresholdKeyMaterial = await IndexedDBManager
          .getNearThresholdKeyMaterialV2First(nearAccountId, deviceNumber)
          .catch(() => null);
        if (!thresholdKeyMaterial) return;

        const relayerUrl = String(context.configs?.relayer?.url || '').trim();
        if (!relayerUrl) return;

        const participantIds = normalizeThresholdEd25519ParticipantIds(thresholdKeyMaterial.participants?.map((p) => p.id));

        onEvent?.({
          step: 2,
          phase: LoginPhase.STEP_2_WEBAUTHN_ASSERTION,
          status: LoginStatus.PROGRESS,
          message: 'Preparing a warm signing session...',
        });

        await webAuthnManager.connectThresholdEd25519SessionLite({
          nearAccountId,
          relayerKeyId: thresholdKeyMaterial.relayerKeyId,
          ...(participantIds ? { participantIds } : {}),
          relayerUrl,
          sessionKind: 'jwt',
          ttlMs: signingSessionPolicy.ttlMs,
          remainingUses: signingSessionPolicy.remainingUses,
        });

        signingSession = await webAuthnManager.getWarmSigningSessionStatus(nearAccountId).catch(() => null) || undefined;
        if (signingSession?.status === 'active') {
          onEvent?.({
            step: 3,
            phase: LoginPhase.STEP_3_SESSION_READY,
            status: LoginStatus.PROGRESS,
            message: 'Warm signing session ready',
          });
        }
      } catch {
        // Best-effort: signing flows can still prompt later.
      }
    };

    const session = options?.session;
    const wantsServerSession = session !== undefined;

    if (wantsServerSession) {
      const relayUrl = (session?.relayUrl || context.configs.relayer.url).trim();
      if (!relayUrl) {
        throw new Error('Missing relayUrl for session-style login');
      }

      const verifyRoute = (session?.route || '/auth/passkey/verify').trim();
      const verifyPath = verifyRoute.startsWith('/') ? verifyRoute : `/${verifyRoute}`;
      const optionsRoute = verifyPath.endsWith('/verify')
        ? `${verifyPath.slice(0, -'/verify'.length)}/options`
        : '/auth/passkey/options';

      const rpId = webAuthnManager.getRpId();
      if (!rpId) {
        throw new Error('Missing rpId for login session mint');
      }

      const loginOptions = await createWebAuthnLoginOptions(relayUrl, optionsRoute, {
        userId: nearAccountId,
        rpId,
      });
      if (!loginOptions.success || !loginOptions.challengeId || !loginOptions.challengeB64u) {
        throw new Error(loginOptions.error || 'Failed to create WebAuthn login options');
      }

      onEvent?.({
        step: 2,
        phase: LoginPhase.STEP_2_WEBAUTHN_ASSERTION,
        status: LoginStatus.PROGRESS,
        message: 'Authenticating with passkey...',
      });

      const authenticatorsForPrompt = prioritizeAuthenticatorsByDeviceNumber(authenticators, baseDeviceNumber);
      const credential = await webAuthnManager.getAuthenticationCredentialsSerialized({
        nearAccountId,
        challengeB64u: loginOptions.challengeB64u,
        allowCredentials: authenticatorsToAllowCredentials(authenticatorsForPrompt),
      });

      const selectedDeviceNumber = resolveDeviceNumberFromCredentialId(
        authenticators,
        credential.rawId,
        baseDeviceNumber,
      );

      await webAuthnManager.setLastUser(nearAccountId, selectedDeviceNumber).catch(() => undefined);
      await webAuthnManager.updateLastLogin(nearAccountId).catch(() => undefined);

      const selectedUserData = await webAuthnManager
        .getUserByDevice(nearAccountId, selectedDeviceNumber)
        .catch(() => userData);

      const v = await verifyWebAuthnLogin(relayUrl, verifyPath, session.kind, {
        challengeId: loginOptions.challengeId,
        webauthnAuthentication: credential,
      });
      if (!v.success || !v.verified) {
        throw new Error(v.error || 'Session verification failed');
      }

      onEvent?.({
        step: 3,
        phase: LoginPhase.STEP_3_SESSION_READY,
        status: LoginStatus.PROGRESS,
        message: 'Session ready',
      });

      const loginResult: LoginResult = {
        success: true,
        loggedInNearAccountId: String(nearAccountId),
        clientNearPublicKey: selectedUserData?.clientNearPublicKey ?? userData.clientNearPublicKey,
        nearAccountId,
        ...(v.jwt ? { jwt: v.jwt } : {}),
      };

      await maybeWarmThresholdSigningSession(selectedDeviceNumber);

      return await finalizeLoginSuccess({
        nearAccountId,
        loginResult: {
          ...(loginResult as any),
          ...(signingSession ? { signingSession } : {}),
        },
        onEvent,
        afterCall,
      });
    }

    await webAuthnManager.setLastUser(nearAccountId, baseDeviceNumber).catch(() => undefined);
    await webAuthnManager.updateLastLogin(nearAccountId).catch(() => undefined);

    await maybeWarmThresholdSigningSession(baseDeviceNumber);

    const loginResult: LoginAndCreateSessionResult = {
      success: true,
      loggedInNearAccountId: String(nearAccountId),
      clientNearPublicKey: userData.clientNearPublicKey,
      nearAccountId,
      ...(signingSession ? { signingSession } : {}),
    };

    return await finalizeLoginSuccess({
      nearAccountId,
      loginResult,
      onEvent,
      afterCall,
    });
  } catch (err: unknown) {
    const errorMessage = getUserFriendlyErrorMessage(err, 'login') || 'Login failed';
    return await finalizeLoginError({
      message: errorMessage,
      error: err,
      onEvent,
      onError,
      afterCall,
    });
  }
}

async function finalizeLoginSuccess(args: {
  nearAccountId: AccountId;
  loginResult: LoginResult;
  onEvent?: (event: LoginSSEvent) => void;
  afterCall?: AfterCall<LoginAndCreateSessionResult>;
}): Promise<LoginAndCreateSessionResult> {
  const { nearAccountId, loginResult, onEvent, afterCall } = args;
  onEvent?.({
    step: 4,
    phase: LoginPhase.STEP_4_LOGIN_COMPLETE,
    status: LoginStatus.SUCCESS,
    message: 'Login completed successfully',
    nearAccountId,
    clientNearPublicKey: loginResult.clientNearPublicKey ?? '',
  });
  await afterCall?.(true, loginResult);
  return loginResult;
}

async function finalizeLoginError(args: {
  message: string;
  error?: unknown;
  onEvent?: (event: LoginSSEvent) => void;
  onError?: (error: Error) => void;
  afterCall?: AfterCall<LoginAndCreateSessionResult>;
  callOnError?: boolean;
  callAfterCall?: boolean;
}): Promise<LoginAndCreateSessionResult> {
  const {
    message,
    error,
    onEvent,
    onError,
    afterCall,
    callOnError = true,
    callAfterCall = true,
  } = args;

  if (callOnError) {
    onError?.(error as any);
  }

  onEvent?.({
    step: 0,
    phase: LoginPhase.LOGIN_ERROR,
    status: LoginStatus.ERROR,
    message,
    error: message,
  });

  if (callAfterCall) {
    await afterCall?.(false);
  }
  return { success: false, error: message };
}

function resolveDeviceNumberFromCredentialId(
  authenticators: ClientAuthenticatorData[],
  credentialRawId: string,
  fallback: number,
): number {
  const rawId = String(credentialRawId || '').trim();
  if (!rawId) return fallback;
  const matched = authenticators.find((a) => a.credentialId === rawId);
  const deviceNumber = matched?.deviceNumber;
  return Number.isSafeInteger(deviceNumber) && (deviceNumber as number) >= 1 ? (deviceNumber as number) : fallback;
}

function prioritizeAuthenticatorsByDeviceNumber(
  authenticators: ClientAuthenticatorData[],
  deviceNumber: number | null
): ClientAuthenticatorData[] {
  if (authenticators.length <= 1) return authenticators;
  if (deviceNumber === null) return authenticators;
  const preferred = authenticators.filter((a) => a.deviceNumber === deviceNumber);
  if (preferred.length === 0) return authenticators;
  const rest = authenticators.filter((a) => a.deviceNumber !== deviceNumber);
  return [...preferred, ...rest];
}

/**
 * High-level login snapshot used by React contexts/UI.
 *
 * Login state is derived from the IndexedDB last-user pointer (no worker dependency).
 */
export async function getLoginSession(
  context: PasskeyManagerContext,
  nearAccountId?: AccountId
): Promise<LoginSession> {
  const login = await getLoginStateInternal(context, nearAccountId);
  const signingSession = login?.nearAccountId
    ? await context.webAuthnManager.getWarmSigningSessionStatus(login.nearAccountId).catch(() => null)
    : null;
  return { login, signingSession };
}

async function getLoginStateInternal(
  context: PasskeyManagerContext,
  nearAccountId?: AccountId
): Promise<LoginState> {
  const { webAuthnManager } = context;
  try {
    const lastUser = await webAuthnManager.getLastUser().catch(() => null);
    const targetAccountId = nearAccountId ?? lastUser?.nearAccountId ?? null;

    if (!lastUser || (targetAccountId && lastUser.nearAccountId !== targetAccountId)) {
      return {
        isLoggedIn: false,
        nearAccountId: targetAccountId || null,
        publicKey: null,
        userData: null,
      };
    }

    const userData = lastUser;
    const publicKey = userData?.clientNearPublicKey || null;
    const isLoggedIn = !!(userData && userData.clientNearPublicKey);

    return {
      isLoggedIn,
      nearAccountId: targetAccountId,
      publicKey,
      userData,
    };
  } catch (error: unknown) {
    console.warn('Error getting login state:', error);
    return {
      isLoggedIn: false,
      nearAccountId: nearAccountId || null,
      publicKey: null,
      userData: null,
    };
  }
}

/**
 * List recently used accounts from IndexedDB.
 *
 * Used for account picker UIs and initial app bootstrap state.
 */
export async function getRecentLogins(
  context: PasskeyManagerContext
): Promise<GetRecentLoginsResult> {
  const { webAuthnManager } = context;
  const allUsersData = await webAuthnManager.getAllUsers();
  const accountIds = allUsersData.map(user => user.nearAccountId);
  const lastUsedAccount = await webAuthnManager.getLastUser();
  return {
    accountIds,
    lastUsedAccount,
  };
}

/**
 * Logout: clears last-user pointer and client-side caches.
 */
export async function logoutAndClearSession(context: PasskeyManagerContext): Promise<void> {
  const { webAuthnManager } = context;
  await IndexedDBManager.clientDB.clearLastProfileSelection().catch(() => undefined);
  try { webAuthnManager.getNonceManager().clear(); } catch {}
  try { clearAllCachedThresholdEd25519AuthSessions(); } catch {}
}
