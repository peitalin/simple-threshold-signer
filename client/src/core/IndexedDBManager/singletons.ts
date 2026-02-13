import { PasskeyClientDBManager } from './passkeyClientDB';
import { PasskeyNearKeysDBManager } from './passkeyNearKeysDB';

// Shared singleton instances for backward compatibility.
export const passkeyClientDB = new PasskeyClientDBManager();
export const passkeyNearKeysDB = new PasskeyNearKeysDBManager();
