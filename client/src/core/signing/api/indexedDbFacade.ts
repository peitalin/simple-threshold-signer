import type {
  AccountSignerRecord,
  AccountSignerStatus,
  ChainAccountRecord,
  ClientAuthenticatorData,
  ClientUserData,
  EnqueueSignerOperationInput,
  ProfileRecord,
  SignerOpOutboxRecord,
  UnifiedIndexedDBManager,
  UpsertAccountSignerInput,
  UpsertChainAccountInput,
  UpsertProfileInput,
} from '../../IndexedDBManager';
import type { AccountId } from '../../types/accountIds';

export type IndexedDbFacadeDeps = {
  indexedDB: UnifiedIndexedDBManager;
};

export async function getProfile(
  deps: IndexedDbFacadeDeps,
  profileId: string,
): Promise<ProfileRecord | null> {
  return await deps.indexedDB.getProfile(profileId);
}

export async function upsertProfile(
  deps: IndexedDbFacadeDeps,
  input: UpsertProfileInput,
): Promise<ProfileRecord> {
  return await deps.indexedDB.upsertProfile(input);
}

export async function upsertChainAccount(
  deps: IndexedDbFacadeDeps,
  input: UpsertChainAccountInput,
): Promise<ChainAccountRecord> {
  return await deps.indexedDB.upsertChainAccount(input);
}

export async function getProfileByAccount(
  deps: IndexedDbFacadeDeps,
  chainId: string,
  accountAddress: string,
): Promise<ProfileRecord | null> {
  return await deps.indexedDB.getProfileByAccount(chainId, accountAddress);
}

export async function upsertAccountSigner(
  deps: IndexedDbFacadeDeps,
  input: UpsertAccountSignerInput,
): Promise<AccountSignerRecord> {
  return await deps.indexedDB.upsertAccountSigner(input);
}

export async function listAccountSigners(
  deps: IndexedDbFacadeDeps,
  args: {
    chainId: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  },
): Promise<AccountSignerRecord[]> {
  return await deps.indexedDB.listAccountSigners(args);
}

export async function setAccountSignerStatus(
  deps: IndexedDbFacadeDeps,
  args: {
    chainId: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
  },
): Promise<AccountSignerRecord | null> {
  return await deps.indexedDB.setAccountSignerStatus(args);
}

export async function enqueueSignerOperation(
  deps: IndexedDbFacadeDeps,
  input: EnqueueSignerOperationInput,
): Promise<SignerOpOutboxRecord> {
  return await deps.indexedDB.enqueueSignerOperation(input);
}

export async function getAllUsers(deps: IndexedDbFacadeDeps): Promise<ClientUserData[]> {
  return await deps.indexedDB.clientDB.listNearAccountProjections();
}

export async function getUserByDevice(
  deps: IndexedDbFacadeDeps,
  nearAccountId: AccountId,
  deviceNumber: number,
): Promise<ClientUserData | null> {
  return await deps.indexedDB.clientDB.getNearAccountProjection(nearAccountId, deviceNumber);
}

export async function getLastUser(
  deps: IndexedDbFacadeDeps,
): Promise<ClientUserData | null> {
  return await deps.indexedDB.clientDB.getLastSelectedNearAccountProjection();
}

export async function getAuthenticatorsByUser(
  deps: IndexedDbFacadeDeps,
  nearAccountId: AccountId,
): Promise<ClientAuthenticatorData[]> {
  return await deps.indexedDB.clientDB.listNearAuthenticators(nearAccountId);
}

export async function updateLastLogin(
  deps: IndexedDbFacadeDeps,
  nearAccountId: AccountId,
): Promise<void> {
  await deps.indexedDB.clientDB.touchLastLoginForNearAccount(nearAccountId);
}

export async function setLastUser(
  deps: IndexedDbFacadeDeps,
  nearAccountId: AccountId,
  deviceNumber: number = 1,
): Promise<void> {
  await deps.indexedDB.clientDB.setLastProfileStateForNearAccount(nearAccountId, deviceNumber);
}
