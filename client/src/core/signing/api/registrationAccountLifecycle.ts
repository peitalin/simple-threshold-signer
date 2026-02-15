import type {
  ClientUserData,
  UnifiedIndexedDBManager,
} from '../../IndexedDBManager';
import type { StoreUserDataInput } from '../../IndexedDBManager/passkeyClientDB';
import type { NearClient } from '../../near/NearClient';
import type { NonceManager } from '../../near/nonceManager';
import { toAccountId, type AccountId } from '../../types/accountIds';
import type { WebAuthnRegistrationCredential } from '../../types';
import { getLastLoggedInDeviceNumber } from '../webauthn/device/getDeviceNumber';
import type { UserPreferencesManager } from './userPreferences';

export type RegistrationAccountLifecycleDeps = {
  indexedDB: UnifiedIndexedDBManager;
  userPreferencesManager: Pick<UserPreferencesManager, 'setCurrentUser' | 'reloadUserSettings'>;
  nonceManager: Pick<NonceManager, 'initializeUser' | 'prefetchBlockheight'>;
  extractCosePublicKey: (attestationObjectBase64url: string) => Promise<Uint8Array>;
};

export type StoreAuthenticatorInput = {
  credentialId: string;
  credentialPublicKey: Uint8Array;
  transports?: string[];
  name?: string;
  nearAccountId: AccountId;
  registered: string;
  syncedAt: string;
  deviceNumber?: number;
};

export async function storeUserData(
  deps: RegistrationAccountLifecycleDeps,
  userData: StoreUserDataInput,
): Promise<void> {
  await deps.indexedDB.clientDB.upsertNearAccountProjection({
    ...userData,
    deviceNumber: userData.deviceNumber ?? 1,
    version: userData.version || 2,
  });
}

export async function initializeCurrentUser(
  deps: RegistrationAccountLifecycleDeps,
  args: { nearAccountId: AccountId; nearClient?: NearClient },
): Promise<void> {
  const accountId = toAccountId(args.nearAccountId);

  // Set as last profile/device for future sessions, preferring the existing pointer.
  let deviceNumberToUse = await getLastLoggedInDeviceNumber(accountId, deps.indexedDB.clientDB).catch(
    () => null as number | null,
  );
  if (deviceNumberToUse === null) {
    const context = await deps.indexedDB.clientDB.resolveNearAccountContext(accountId).catch(() => null);
    const profile = context?.profileId
      ? await deps.indexedDB.clientDB.getProfile(context.profileId).catch(() => null)
      : null;
    const defaultDevice = Number(profile?.defaultDeviceNumber);
    deviceNumberToUse =
      Number.isSafeInteger(defaultDevice) && defaultDevice >= 1
        ? defaultDevice
        : 1;
  }
  await deps.indexedDB.clientDB.setLastProfileStateForNearAccount(accountId, deviceNumberToUse);

  // Set as current user for immediate use
  deps.userPreferencesManager.setCurrentUser(accountId);
  // Ensure confirmation preferences are loaded before callers read them (best-effort)
  await deps.userPreferencesManager.reloadUserSettings().catch(() => undefined);

  // Initialize NonceManager with the selected user's public key (best-effort)
  const userData = await deps.indexedDB.clientDB
    .getNearAccountProjection(accountId, deviceNumberToUse)
    .catch(() => null);
  if (userData && userData.clientNearPublicKey) {
    deps.nonceManager.initializeUser(accountId, userData.clientNearPublicKey);
  }

  // Prefetch block height for better UX (non-fatal if it fails and nearClient is provided)
  if (args.nearClient) {
    await deps.nonceManager
      .prefetchBlockheight(args.nearClient)
      .catch((prefetchErr) =>
        console.debug(
          'Nonce prefetch after authentication state initialization failed (non-fatal):',
          prefetchErr,
        ),
      );
  }
}

export async function registerUser(
  deps: RegistrationAccountLifecycleDeps,
  storeUserDataInput: StoreUserDataInput,
): Promise<ClientUserData> {
  return await deps.indexedDB.clientDB.upsertNearAccountProjection(storeUserDataInput);
}

export async function storeAuthenticator(
  deps: RegistrationAccountLifecycleDeps,
  authenticatorData: StoreAuthenticatorInput,
): Promise<void> {
  const deviceNumber = Number(authenticatorData.deviceNumber);
  const normalizedDeviceNumber =
    Number.isSafeInteger(deviceNumber) && deviceNumber >= 1 ? deviceNumber : 1;
  const authData = {
    ...authenticatorData,
    nearAccountId: toAccountId(authenticatorData.nearAccountId),
    deviceNumber: normalizedDeviceNumber, // Default to device 1 (1-indexed)
  };
  await deps.indexedDB.clientDB.upsertNearAuthenticator(authData);
}

export function extractUsername(nearAccountId: AccountId): string {
  return String(nearAccountId).split('.')[0] || '';
}

export async function atomicOperation<T>(
  deps: RegistrationAccountLifecycleDeps,
  callback: (db: any) => Promise<T>,
): Promise<T> {
  return await deps.indexedDB.clientDB.atomicOperation(callback);
}

export async function rollbackUserRegistration(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<void> {
  await deps.indexedDB.clientDB.rollbackNearAccountRegistration(nearAccountId);
}

export async function hasPasskeyCredential(
  deps: RegistrationAccountLifecycleDeps,
  nearAccountId: AccountId,
): Promise<boolean> {
  return await deps.indexedDB.clientDB.hasNearPasskeyCredential(nearAccountId);
}

export async function atomicStoreRegistrationData(
  deps: RegistrationAccountLifecycleDeps,
  args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    publicKey: string;
  },
): Promise<void> {
  await atomicOperation(deps, async () => {
    // Store credential for authentication
    const credentialId: string = args.credential.rawId;
    const attestationB64u: string = args.credential.response.attestationObject;
    const transports: string[] = args.credential.response?.transports;
    const credentialPublicKey = await deps.extractCosePublicKey(attestationB64u);

    // Persist profile/account mapping first.
    await storeUserData(deps, {
      nearAccountId: args.nearAccountId,
      deviceNumber: 1,
      clientNearPublicKey: args.publicKey,
      lastUpdated: Date.now(),
      passkeyCredential: {
        id: args.credential.id,
        rawId: credentialId,
      },
      version: 2,
    });

    await storeAuthenticator(deps, {
      nearAccountId: args.nearAccountId,
      credentialId: credentialId,
      credentialPublicKey,
      transports,
      name: `Passkey for ${extractUsername(args.nearAccountId)}`,
      registered: new Date().toISOString(),
      syncedAt: new Date().toISOString(),
    });

    return true;
  });
}
