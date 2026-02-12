import type { PasskeyClientDBManager } from '../../../IndexedDBManager';
import { toAccountId, type AccountId } from '../../../types/accountIds';

export function parseDeviceNumber(
  value: unknown,
  options: { min?: number } = {},
): number | null {
  const deviceNumber = Number(value);
  const min = options.min ?? 1;
  if (!Number.isSafeInteger(deviceNumber) || deviceNumber < min) {
    return null;
  }
  return deviceNumber;
}

/**
 * Return the deviceNumber for the last logged-in user for the given account.
 * This uses the app-state "last user" pointer only; if it does not match the
 * requested account, an error is thrown instead of silently falling back.
 */
export async function getLastLoggedInDeviceNumber(
  nearAccountId: AccountId | string,
  clientDB: PasskeyClientDBManager,
): Promise<number> {
  const accountId = toAccountId(nearAccountId);

  // V2-first: use profile-scoped last-user pointer when available.
  const lastProfile = await clientDB.getLastProfileState().catch(() => null);
  if (lastProfile?.profileId) {
    const expectedProfileId = `legacy-near:${String(accountId)}`;
    const profileDevice = parseDeviceNumber(lastProfile.deviceNumber, { min: 1 });
    if (lastProfile.profileId === expectedProfileId && profileDevice !== null) {
      return profileDevice;
    }
    const fromV2 = await clientDB.getUserByDevice(accountId, lastProfile.deviceNumber).catch(() => null);
    if (fromV2 && fromV2.nearAccountId === accountId) {
      const deviceNumber = parseDeviceNumber(fromV2.deviceNumber, { min: 1 });
      if (deviceNumber !== null) return deviceNumber;
    }
  }

  const last = await clientDB.getLastUser();
  if (last && last.nearAccountId === accountId) {
    const deviceNumber = parseDeviceNumber(last.deviceNumber, { min: 1 });
    if (deviceNumber !== null) {
      return deviceNumber;
    }
  }
  throw new Error(`No last user session for account ${accountId}`);
}
