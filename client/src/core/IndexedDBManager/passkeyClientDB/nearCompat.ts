import type { AccountId } from '../../types/accountIds';
import { toAccountId } from '../../types/accountIds';
import type { IDBPDatabase } from 'idb';
import type {
  AccountSignerRecord,
  ChainAccountRecord,
  ClientAuthenticatorData,
  ClientUserData,
  DerivedAddressRecord,
  LastProfileState,
  ProfileAuthenticatorRecord,
  ProfileRecord,
  UpsertAccountSignerInput,
  UpsertChainAccountInput,
  UpsertProfileInput,
  UserPreferences,
} from '../passkeyClientDB.types';
import { LEGACY_NEAR_PROFILE_PREFIX } from './schema';

interface LegacyLastUserState {
  accountId: AccountId;
  deviceNumber: number;
}

function normalizeLastUserScope(scope: unknown): string | null {
  const normalized = typeof scope === 'string' ? scope.trim() : '';
  if (!normalized || normalized === 'null') return null;
  return normalized;
}

function parseEip155ChainId(raw: unknown): string | null {
  const value = String(raw || '').trim().toLowerCase();
  if (!value) return null;
  if (/^\d+$/.test(value)) return value;
  if (!/^0x[0-9a-f]+$/.test(value)) return null;
  const asNumber = Number.parseInt(value, 16);
  if (!Number.isSafeInteger(asNumber) || asNumber < 0) return null;
  return String(asNumber);
}

function normalizeAccountAddress(address: unknown): string {
  return String(address || '').trim().toLowerCase();
}

export function buildLegacyNearProfileId(accountId: AccountId): string {
  return `${LEGACY_NEAR_PROFILE_PREFIX}:${String(accountId)}`;
}

export function parseLegacyLastUserState(raw: unknown): LegacyLastUserState | null {
  if (raw == null) return null;

  if (typeof raw === 'string') {
    const accountIdStr = raw.trim();
    if (!accountIdStr) return null;
    try {
      return { accountId: toAccountId(accountIdStr), deviceNumber: 1 };
    } catch {
      return null;
    }
  }

  if (typeof raw !== 'object') return null;

  const accountIdStr = typeof (raw as any).accountId === 'string' ? String((raw as any).accountId).trim() : '';
  if (!accountIdStr) return null;

  let accountId: AccountId;
  try {
    accountId = toAccountId(accountIdStr);
  } catch {
    return null;
  }

  const deviceNumberRaw = (raw as any).deviceNumber;
  const deviceNumber = Number(deviceNumberRaw);
  if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return null;

  return { accountId, deviceNumber };
}

export function parseLastProfileState(raw: unknown): LastProfileState | null {
  if (raw == null || typeof raw !== 'object') return null;

  const profileId = typeof (raw as any).profileId === 'string'
    ? String((raw as any).profileId).trim()
    : '';
  if (!profileId) return null;

  const deviceNumberRaw = (raw as any).deviceNumber;
  const deviceNumber = Number(deviceNumberRaw);
  if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return null;

  const scope = normalizeLastUserScope((raw as any).scope);
  return scope != null
    ? { profileId, deviceNumber, scope }
    : { profileId, deviceNumber };
}

export function inferNearChainId(
  nearAccountId: AccountId,
  networkHint?: UserPreferences['useNetwork'],
): string {
  if (networkHint === 'mainnet') return 'near:mainnet';
  if (networkHint === 'testnet') return 'near:testnet';
  return String(nearAccountId).endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
}

export function inferTargetChainIdFromLegacyDerivedAddress(rec: DerivedAddressRecord): string {
  const namespace = String(rec.namespace || '').trim().toLowerCase();
  const chainRef = String(rec.chainRef || '').trim();
  const path = String(rec.path || '').trim().toLowerCase();
  const evmChainFromPath = (() => {
    const match = path.match(/^evm:([^:]+):/);
    return match?.[1] || null;
  })();

  if (namespace === 'evm' || path.startsWith('evm:')) {
    const chainId = parseEip155ChainId(chainRef || evmChainFromPath || '');
    return chainId ? `eip155:${chainId}` : 'eip155:unknown';
  }
  if (namespace === 'solana' || path.startsWith('solana:')) return 'solana:unknown';
  if (namespace === 'zcash' || path.startsWith('zcash:')) return 'zcash:unknown';
  if (namespace === 'tempo' || path.startsWith('tempo:')) return 'tempo:unknown';
  return 'unknown:derived';
}

export function getNearChainCandidates(accountId: AccountId): string[] {
  const preferred = inferNearChainId(accountId);
  return preferred === 'near:testnet'
    ? ['near:testnet', 'near:mainnet']
    : ['near:mainnet', 'near:testnet'];
}

export function mapProfileAuthenticatorToLegacy(
  profileAuthenticator: ProfileAuthenticatorRecord,
  nearAccountId: AccountId,
): ClientAuthenticatorData {
  return {
    nearAccountId,
    deviceNumber: profileAuthenticator.deviceNumber,
    credentialId: profileAuthenticator.credentialId,
    credentialPublicKey: profileAuthenticator.credentialPublicKey,
    transports: profileAuthenticator.transports,
    name: profileAuthenticator.name,
    registered: profileAuthenticator.registered,
    syncedAt: profileAuthenticator.syncedAt,
  };
}

interface UpsertLegacyNearUserProjectionOperations {
  upsertProfile: (input: UpsertProfileInput) => Promise<unknown>;
  upsertChainAccount: (input: UpsertChainAccountInput) => Promise<unknown>;
  getAccountSigner: (args: {
    chainId: string;
    accountAddress: string;
    signerId: string;
  }) => Promise<AccountSignerRecord | null>;
  upsertAccountSigner: (input: UpsertAccountSignerInput) => Promise<unknown>;
}

export async function upsertLegacyNearUserProjection(args: {
  userData: ClientUserData;
  ops: UpsertLegacyNearUserProjectionOperations;
}): Promise<void> {
  const { userData, ops } = args;
  const accountId = toAccountId(userData.nearAccountId);
  const deviceNumber = Number(userData.deviceNumber);
  if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) {
    throw new Error('PasskeyClientDB: deviceNumber must be an integer >= 1');
  }

  const profileId = buildLegacyNearProfileId(accountId);
  const chainId = inferNearChainId(accountId, userData.preferences?.useNetwork);
  const accountAddress = normalizeAccountAddress(accountId);
  const signerId = String(userData.passkeyCredential?.rawId || '').trim()
    || `legacy-device-${deviceNumber}`;

  await ops.upsertProfile({
    profileId,
    defaultDeviceNumber: deviceNumber,
    passkeyCredential: userData.passkeyCredential,
    ...(userData.preferences ? { preferences: userData.preferences } : {}),
  });

  await ops.upsertChainAccount({
    profileId,
    chainId,
    accountAddress,
    accountModel: 'near-native',
    isPrimary: true,
    legacyNearAccountId: accountId,
  });

  const existingSigner = await ops.getAccountSigner({
    chainId,
    accountAddress,
    signerId,
  }).catch(() => null);
  await ops.upsertAccountSigner({
    profileId,
    chainId,
    accountAddress,
    signerId,
    signerSlot: deviceNumber,
    signerType: 'passkey',
    status: 'active',
    metadata: {
      ...(existingSigner?.metadata || {}),
      clientNearPublicKey: userData.clientNearPublicKey,
      passkeyCredentialId: userData.passkeyCredential?.id,
      passkeyCredentialRawId: userData.passkeyCredential?.rawId,
      legacyNearAccountId: accountId,
    },
    mutation: { routeThroughOutbox: false },
  });
}

export async function buildLegacyNearUserFromV2(args: {
  db: IDBPDatabase;
  nearAccountId: AccountId;
  deviceNumber?: number;
  stores: {
    chainAccountsStore: string;
    profilesStore: string;
    accountSignersStore: string;
  };
}): Promise<ClientUserData | null> {
  const { db, nearAccountId, deviceNumber, stores } = args;
  const accountId = toAccountId(nearAccountId);
  const accountAddress = normalizeAccountAddress(accountId);

  for (const chainId of getNearChainCandidates(accountId)) {
    const tx = db.transaction(stores.chainAccountsStore, 'readonly');
    const idx = tx.store.index('chainId_accountAddress');
    const chainAccount = await idx.get([chainId, accountAddress]) as ChainAccountRecord | undefined;
    if (!chainAccount?.profileId) continue;

    const profile = await db.get(stores.profilesStore, chainAccount.profileId) as ProfileRecord | undefined;
    if (!profile) continue;

    const signerTx = db.transaction(stores.accountSignersStore, 'readonly');
    const signerStore = signerTx.store;
    const activeSigners = await signerStore
      .index('chainId_accountAddress_status')
      .getAll([chainId, accountAddress, 'active']) as AccountSignerRecord[];
    if (!activeSigners.length) continue;

    const selectedSigner = (() => {
      if (typeof deviceNumber === 'number') {
        return activeSigners.find((row) => row.signerSlot === deviceNumber);
      }
      const preferredSlot = Number.isSafeInteger(profile.defaultDeviceNumber)
        ? profile.defaultDeviceNumber
        : 1;
      return (
        activeSigners.find((row) => row.signerSlot === preferredSlot) ||
        activeSigners
          .slice()
          .sort((a, b) => a.signerSlot - b.signerSlot)[0]
      );
    })();
    if (!selectedSigner) continue;

    const metadata = selectedSigner.metadata || {};
    const passkeyCredentialRawId = typeof metadata.passkeyCredentialRawId === 'string'
      ? metadata.passkeyCredentialRawId
      : selectedSigner.signerId;
    const passkeyCredentialId = typeof metadata.passkeyCredentialId === 'string'
      ? metadata.passkeyCredentialId
      : profile.passkeyCredential?.id || passkeyCredentialRawId;
    const clientNearPublicKey = typeof metadata.clientNearPublicKey === 'string'
      ? metadata.clientNearPublicKey
      : '';

    return {
      nearAccountId: accountId,
      deviceNumber: selectedSigner.signerSlot,
      version: 2,
      registeredAt: profile.createdAt,
      lastLogin: profile.updatedAt,
      lastUpdated: profile.updatedAt,
      clientNearPublicKey,
      passkeyCredential: {
        id: passkeyCredentialId,
        rawId: passkeyCredentialRawId,
      },
      preferences: profile.preferences,
    };
  }

  return null;
}

export async function backfillCoreFromLegacyUserRecord(args: {
  db: IDBPDatabase;
  userData: ClientUserData;
  stores: {
    profilesStore: string;
    chainAccountsStore: string;
    accountSignersStore: string;
  };
}): Promise<void> {
  const { db, userData, stores } = args;
  const accountId = toAccountId(userData.nearAccountId);
  const profileId = buildLegacyNearProfileId(accountId);
  const chainId = inferNearChainId(accountId, userData.preferences?.useNetwork);
  const accountAddress = normalizeAccountAddress(accountId);
  const signerId = String(userData.passkeyCredential?.rawId || '').trim() || `legacy-device-${userData.deviceNumber}`;
  const now = Date.now();

  const existingProfile = await db.get(stores.profilesStore, profileId) as ProfileRecord | undefined;
  const profile: ProfileRecord = {
    profileId,
    defaultDeviceNumber: userData.deviceNumber,
    passkeyCredential: userData.passkeyCredential,
    preferences: userData.preferences,
    createdAt: existingProfile?.createdAt ?? userData.registeredAt ?? now,
    updatedAt: now,
  };
  await db.put(stores.profilesStore, profile);

  const existingChain = await db.get(
    stores.chainAccountsStore,
    [profileId, chainId, accountAddress],
  ) as ChainAccountRecord | undefined;
  const chainAccount: ChainAccountRecord = {
    profileId,
    chainId,
    accountAddress,
    accountModel: 'near-native',
    isPrimary: existingChain?.isPrimary ?? true,
    createdAt: existingChain?.createdAt ?? now,
    updatedAt: now,
    legacyNearAccountId: accountId,
  };
  await db.put(stores.chainAccountsStore, chainAccount);

  const existingSigner = await db.get(
    stores.accountSignersStore,
    [chainId, accountAddress, signerId],
  ) as AccountSignerRecord | undefined;
  const signerMetadata: Record<string, unknown> = {
    ...(existingSigner?.metadata || {}),
    clientNearPublicKey: userData.clientNearPublicKey,
    passkeyCredentialId: userData.passkeyCredential?.id,
    passkeyCredentialRawId: userData.passkeyCredential?.rawId,
    legacyNearAccountId: accountId,
  };
  const signer: AccountSignerRecord = {
    profileId,
    chainId,
    accountAddress,
    signerId,
    signerSlot: userData.deviceNumber,
    signerType: 'passkey',
    status: 'active',
    addedAt: existingSigner?.addedAt ?? now,
    updatedAt: now,
    metadata: signerMetadata,
  };
  await db.put(stores.accountSignersStore, signer);
}

export async function backfillProfileAuthenticatorFromLegacyRecord(args: {
  db: IDBPDatabase;
  authenticatorData: ClientAuthenticatorData;
  profileAuthenticatorStore: string;
}): Promise<void> {
  const { db, authenticatorData, profileAuthenticatorStore } = args;
  const accountId = toAccountId(authenticatorData.nearAccountId);
  const profileId = buildLegacyNearProfileId(accountId);
  const record: ProfileAuthenticatorRecord = {
    profileId,
    deviceNumber: authenticatorData.deviceNumber,
    credentialId: authenticatorData.credentialId,
    credentialPublicKey: authenticatorData.credentialPublicKey,
    transports: authenticatorData.transports,
    name: authenticatorData.name,
    registered: authenticatorData.registered,
    syncedAt: authenticatorData.syncedAt,
  };
  await db.put(profileAuthenticatorStore, record);
}
