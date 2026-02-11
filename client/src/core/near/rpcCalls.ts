/**
 * NEAR RPC helpers
 *
 * This file centralizes helper calls made to the NEAR RPC (account existence checks,
 * access key polling, tx context fetch, etc).
 *
 * WebAuthn contract verification calls have been removed from the lite threshold-signer
 * stack; relay-authenticated flows should use standard WebAuthn verification endpoints.
 */

import type { NearClient } from './NearClient';
import type { SignedTransaction } from './NearClient';
import type { AccountId } from '../types/accountIds';
import type {
  WebAuthnRegistrationCredential,
  WebAuthnAuthenticationCredential
} from '../types/webauthn';
import type { PasskeyManagerContext } from '../TatchiPasskey';
import type { ConfirmationConfig } from '../types/signer-worker';
import type { FinalExecutionOutcome } from '@near-js/types';

import { TransactionContext } from '../types/rpc';
import { DEFAULT_WAIT_STATUS } from '../types/rpc';
import { removePrfOutputGuard } from '../signing/webauthn/credentials/helpers';
import { errorMessage } from '../../../../shared/src/utils/errors';
import { ensureEd25519Prefix } from '../../../../shared/src/utils/validation';
import { ActionType } from '../types/actions';
import {
  DeviceLinkingPhase,
  DeviceLinkingStatus,
  type DeviceLinkingSSEEvent,
  ActionPhase,
} from '../types/sdkSentEvents';

export async function fetchNonceBlockHashAndHeight({ nearClient, nearPublicKeyStr, nearAccountId }: {
  nearClient: NearClient,
  nearPublicKeyStr: string,
  nearAccountId: AccountId
}): Promise<TransactionContext> {
  // Get access key and transaction block info concurrently
  const [accessKeyInfo, txBlockInfo] = await Promise.all([
    nearClient.viewAccessKey(nearAccountId, nearPublicKeyStr)
      .catch(e => { throw new Error(`Failed to fetch Access Key`) }),
    nearClient.viewBlock({ finality: 'final' })
      .catch(e => { throw new Error(`Failed to fetch Block Info`) })
  ]);
  if (!accessKeyInfo || accessKeyInfo.nonce === undefined) {
    throw new Error(`Access key not found or invalid for account ${nearAccountId} with public key ${nearPublicKeyStr}. Response: ${JSON.stringify(accessKeyInfo)}`);
  }
  const nextNonce = (BigInt(accessKeyInfo.nonce) + BigInt(1)).toString();
  const txBlockHeight = String(txBlockInfo.header.height);
  const txBlockHash = txBlockInfo.header.hash; // Keep original base58 string

  return {
    nearPublicKeyStr,
    accessKeyInfo,
    nextNonce,
    txBlockHeight,
    txBlockHash,
  };
}

// ===========================
// ACCESS KEY HELPERS
// ===========================

export type AccessKeyWaitOptions = {
  attempts?: number;
  delayMs?: number;
};

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

function isAccessKeyNotFoundError(err: unknown): boolean {
  const msg = String(errorMessage(err) || '').toLowerCase();
  if (!msg) return false;

  // Common NEAR node / near-api-js phrasing for missing access keys.
  if (msg.includes('unknown access key') || msg.includes('unknown_access_key') || msg.includes('unknownaccesskey')) {
    return true;
  }
  if (msg.includes('accesskeydoesnotexist')) return true;
  if (msg.includes('access key does not exist')) return true;
  if (msg.includes("access key doesn't exist")) return true;
  if (msg.includes('access key not found')) return true;
  if (msg.includes('no such access key')) return true;
  if (msg.includes('viewing access key') && msg.includes('does not exist') && !msg.includes('account')) return true;

  return false;
}

export async function hasAccessKey(
  nearClient: NearClient,
  nearAccountId: string,
  publicKey: string,
  opts?: AccessKeyWaitOptions,
): Promise<boolean> {
  const expected = ensureEd25519Prefix(publicKey);
  if (!expected) return false;

  const attempts = Math.max(1, Math.floor(opts?.attempts ?? 6));
  const delayMs = Math.max(50, Math.floor(opts?.delayMs ?? 750));

  for (let i = 0; i < attempts; i++) {
    try {
      await nearClient.viewAccessKey(nearAccountId, expected);
      return true;
    } catch {
      // tolerate transient view errors during propagation; retry
    }
    if (i < attempts - 1) {
      await sleep(delayMs);
    }
  }
  return false;
}

export async function waitForAccessKeyAbsent(
  nearClient: NearClient,
  nearAccountId: string,
  publicKey: string,
  opts?: AccessKeyWaitOptions,
): Promise<boolean> {
  const expected = ensureEd25519Prefix(publicKey);
  if (!expected) return true;

  const attempts = Math.max(1, Math.floor(opts?.attempts ?? 6));
  const delayMs = Math.max(50, Math.floor(opts?.delayMs ?? 650));

  for (let i = 0; i < attempts; i++) {
    try {
      await nearClient.viewAccessKey(nearAccountId, expected);
    } catch (err: unknown) {
      if (isAccessKeyNotFoundError(err)) return true;
      // tolerate transient view errors during propagation; retry
    }
    if (i < attempts - 1) {
      await sleep(delayMs);
    }
  }
  return false;
}

// ===========================
// ACCOUNT HELPERS
// ===========================

/**
 * Best-effort on-chain account existence check.
 *
 * Used to short-circuit UX flows (e.g. registration) before prompting the user.
 * Returns `false` on unknown/non-deterministic failures so that downstream flows
 * can rely on the relay/contract for final enforcement.
 */
export async function checkNearAccountExistsBestEffort(
  nearClient: NearClient,
  nearAccountId: string,
  opts?: { attempts?: number; delayMs?: number },
): Promise<boolean> {
  const isNotFound = (m: string) => /does not exist|UNKNOWN_ACCOUNT|unknown\s+account/i.test(m);
  const isRetryable = (m: string) =>
    /server error|internal|temporar|timeout|too many requests|429|empty response|rpc request failed|failed to fetch/i.test(m);

  const attempts = Math.max(1, Math.floor(opts?.attempts ?? 2));
  const baseDelayMs = Math.max(50, Math.floor(opts?.delayMs ?? 150));

  for (let i = 1; i <= attempts; i++) {
    try {
      await nearClient.viewAccount(nearAccountId);
      return true;
    } catch (err: unknown) {
      const msg = errorMessage(err);
      const details = (err && typeof err === 'object' && 'details' in err)
        ? (err as { details?: unknown }).details
        : undefined;
      let detailsBlob = '';
      if (details) {
        try {
          detailsBlob = typeof details === 'string' ? details : JSON.stringify(details);
        } catch {
          detailsBlob = '';
        }
      }
      const combined = `${msg}\n${detailsBlob}`.trim();
      if (isNotFound(combined)) return false;
      if (isRetryable(combined) && i < attempts) {
        const backoffMs = baseDelayMs * Math.pow(2, i - 1);
        await sleep(backoffMs);
        continue;
      }
      console.warn(`[rpcCalls] Account existence check failed for '${nearAccountId}'; continuing:`, err);
      return false;
    }
  }

  return false;
}

export async function createWebAuthnLoginOptions(
  relayServerUrl: string,
  routePath: string,
  args: { userId: string; rpId: string; ttlMs?: number },
): Promise<{
  success: boolean;
  challengeId?: string;
  challengeB64u?: string;
  expiresAtMs?: number;
  error?: string;
}> {
  try {
    const user_id = String(args.userId || '').trim();
    const rp_id = String(args.rpId || '').trim();
    if (!user_id) throw new Error('Missing userId');
    if (!rp_id) throw new Error('Missing rpId');

    const url = `${relayServerUrl.replace(/\/$/, '')}${routePath.startsWith('/') ? routePath : `/${routePath}`}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id,
        rp_id,
        ...(args.ttlMs !== undefined ? { ttl_ms: args.ttlMs } : {}),
      }),
    });

    const data: any = await response.json().catch(() => ({}));
    if (!response.ok) {
      return {
        success: false,
        error: data?.message || `HTTP ${response.status}`,
      };
    }
    if (data?.ok !== true) {
      return { success: false, error: data?.message || 'Failed to create login options' };
    }

    const expiresAtMs = (() => {
      const n = typeof data?.expiresAtMs === 'number' ? data.expiresAtMs : Number(data?.expiresAtMs);
      return Number.isFinite(n) ? Math.floor(n) : undefined;
    })();

    return {
      success: true,
      challengeId: typeof data?.challengeId === 'string' ? data.challengeId : undefined,
      challengeB64u: typeof data?.challengeB64u === 'string' ? data.challengeB64u : undefined,
      expiresAtMs,
    };
  } catch (error: any) {
    return { success: false, error: error?.message || 'Failed to create login options' };
  }
}

export async function verifyWebAuthnLogin(
  relayServerUrl: string,
  routePath: string,
  sessionKind: 'jwt' | 'cookie',
  args: { challengeId: string; webauthnAuthentication: WebAuthnAuthenticationCredential },
): Promise<{
  success: boolean;
  verified?: boolean;
  jwt?: string;
  error?: string;
}> {
  try {
    const challengeId = String(args.challengeId || '').trim();
    if (!challengeId) throw new Error('Missing challengeId');

    // Strip PRF outputs before sending to the relay.
    const redacted = removePrfOutputGuard(args.webauthnAuthentication);

    // Normalize authenticatorAttachment and userHandle to null for server schema
    const webauthn_authentication = {
      ...redacted,
      authenticatorAttachment: redacted.authenticatorAttachment ?? null,
      response: {
        ...redacted.response,
        userHandle: redacted.response.userHandle ?? null,
      }
    };

    const url = `${relayServerUrl.replace(/\/$/, '')}${routePath.startsWith('/') ? routePath : `/${routePath}`}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: sessionKind === 'cookie' ? 'include' : 'omit',
      body: JSON.stringify({
        sessionKind,
        challengeId,
        webauthn_authentication,
      }),
    });

    const data: any = await response.json().catch(() => ({}));
    if (!response.ok) {
      return { success: false, error: data?.message || `HTTP ${response.status}` };
    }
    if (data?.ok !== true || data?.verified !== true) {
      return { success: false, verified: false, error: data?.message || 'Authentication verification failed' };
    }
    return { success: true, verified: true, jwt: data?.jwt };
  } catch (error: any) {
    return { success: false, error: error?.message || 'Failed to verify login' };
  }
}

export async function thresholdEd25519Keygen(
  relayServerUrl: string,
  args: {
    clientVerifyingShareB64u: string;
    nearAccountId: string;
    rpId: string;
    keygenSessionId: string;
    webauthnAuthentication: WebAuthnAuthenticationCredential;
  },
): Promise<{
  ok: boolean;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  participantIds?: number[];
  relayerKeyId?: string;
  publicKey?: string;
  relayerVerifyingShareB64u?: string;
  code?: string;
  message?: string;
  error?: string;
}> {
  try {
    const base = String(relayServerUrl || '').trim().replace(/\/$/, '');
    if (!base) throw new Error('Missing relayServerUrl');

    const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
    if (!clientVerifyingShareB64u) throw new Error('Missing clientVerifyingShareB64u');

    const nearAccountId = String(args.nearAccountId || '').trim();
    if (!nearAccountId) throw new Error('Missing nearAccountId');

    const rpId = String(args.rpId || '').trim();
    if (!rpId) throw new Error('Missing rpId');

    const keygenSessionId = String(args.keygenSessionId || '').trim();
    if (!keygenSessionId) throw new Error('Missing keygenSessionId');

    // Never send PRF outputs to the relay.
    const webauthn_authentication = removePrfOutputGuard(args.webauthnAuthentication);

    const url = `${base}/threshold-ed25519/keygen`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        clientVerifyingShareB64u,
        nearAccountId,
        rpId,
        keygenSessionId,
        webauthn_authentication,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return { ok: false, error: `HTTP ${response.status}: ${errorText}` };
    }

    const json = await response.json();
    return {
      ok: !!json?.ok,
      clientParticipantId: json?.clientParticipantId,
      relayerParticipantId: json?.relayerParticipantId,
      participantIds: json?.participantIds,
      relayerKeyId: json?.relayerKeyId,
      publicKey: json?.publicKey,
      relayerVerifyingShareB64u: json?.relayerVerifyingShareB64u,
      code: json?.code,
      message: json?.message,
    };
  } catch (error: any) {
    return { ok: false, error: error?.message || 'Failed to keygen threshold-ed25519' };
  }
}

export async function thresholdEcdsaKeygen(
  relayServerUrl: string,
  args: {
    userId: string;
    rpId: string;
    keygenSessionId: string;
    clientVerifyingShareB64u: string;
    webauthnAuthentication: WebAuthnAuthenticationCredential;
  },
): Promise<{
  ok: boolean;
  participantIds?: number[];
  relayerKeyId?: string;
  groupPublicKeyB64u?: string;
  ethereumAddress?: string;
  relayerVerifyingShareB64u?: string;
  code?: string;
  message?: string;
  error?: string;
}> {
  try {
    const base = String(relayServerUrl || '').trim().replace(/\/$/, '');
    if (!base) throw new Error('Missing relayServerUrl');

    const userId = String(args.userId || '').trim();
    if (!userId) throw new Error('Missing userId');

    const rpId = String(args.rpId || '').trim();
    if (!rpId) throw new Error('Missing rpId');

    const keygenSessionId = String(args.keygenSessionId || '').trim();
    if (!keygenSessionId) throw new Error('Missing keygenSessionId');

    const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
    if (!clientVerifyingShareB64u) throw new Error('Missing clientVerifyingShareB64u');

    // Never send PRF outputs to the relay.
    const webauthn_authentication = removePrfOutputGuard(args.webauthnAuthentication);

    const url = `${base}/threshold-ecdsa/keygen`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        userId,
        rpId,
        keygenSessionId,
        clientVerifyingShareB64u,
        webauthn_authentication,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return { ok: false, error: `HTTP ${response.status}: ${errorText}` };
    }

    const json = await response.json();
    return {
      ok: !!json?.ok,
      participantIds: json?.participantIds,
      relayerKeyId: json?.relayerKeyId,
      groupPublicKeyB64u: json?.groupPublicKeyB64u,
      ethereumAddress: json?.ethereumAddress,
      relayerVerifyingShareB64u: json?.relayerVerifyingShareB64u,
      code: json?.code,
      message: json?.message,
    };
  } catch (error: any) {
    return { ok: false, error: error?.message || 'Failed to keygen threshold-ecdsa' };
  }
}

// ===========================
// CONTRACT CALL RESPONSES
// ===========================

export interface DeviceLinkingResult {
  linkedAccountId: string;
  deviceNumber: number;
}

export interface CredentialIdsResult {
  credentialIds: string[];
}

export interface AuthenticatorsResult {
  authenticators: Array<[string, ContractStoredAuthenticator]>;
}

// Legacy on-chain authenticator shape (web3authn contract).
// The lite relayer stack no longer stores authenticators on-chain, but some older helpers/tests
// still reference this type via `AuthenticatorsResult`.
export type ContractStoredAuthenticator = Record<string, unknown>;

export type RecoveryAttemptStatus =
  | "Started"
  | "VerifyingDkim"
  | "VerifyingZkEmail"
  | "DkimFailed"
  | "ZkEmailFailed"
  | "PolicyFailed"
  | "Recovering"
  | "AwaitingMoreEmails"
  | "Complete"
  | "Failed";

export type RecoveryAttempt = {
  request_id: string;
  status: RecoveryAttemptStatus | string;
  created_at_ms: number;
  updated_at_ms: number;
  error?: string | null;
  /**
   * 32-byte SHA-256 hash of "<canonical_from>|<account_id_lower>".
   * Returned by newer EmailRecoverer contracts (replaces `from_address`).
   */
  from_address_hash?: number[] | null;
  /** Legacy field (string email address). */
  from_address?: string | null;
  email_timestamp_ms?: number | null;
  new_public_key?: string | null;
};

function normalizeByteArray(input: unknown): number[] | null | undefined {
  if (input == null) return input as null | undefined;

  if (Array.isArray(input)) {
    return input.map((v) => Number(v)).filter((v) => Number.isFinite(v));
  }

  if (typeof input === 'string' && input) {
    try {
      const bytes =
        typeof Buffer !== 'undefined'
          ? Buffer.from(input, 'base64')
          : Uint8Array.from(atob(input), (c) => c.charCodeAt(0));
      const arr = bytes instanceof Uint8Array ? Array.from(bytes) : Array.from(new Uint8Array(bytes));
      return arr;
    } catch {
      return undefined;
    }
  }

  return undefined;
}


export async function getEmailRecoveryAttempt(
  nearClient: NearClient,
  accountId: string,
  requestId: string
): Promise<RecoveryAttempt | null> {
  const raw = await nearClient.view<{ request_id: string }, Omit<RecoveryAttempt, 'status'> & { status: any } | null>({
    account: accountId,
    method: 'get_recovery_attempt',
    args: { request_id: requestId },
  });

  if (!raw) return null;

  // Normalization logic for status (string or object enum)
  const statusRaw = raw.status;
  const status = (() => {
    if (typeof statusRaw === 'string') return statusRaw.trim();
    if (statusRaw && typeof statusRaw === 'object') {
      const keys = Object.keys(statusRaw as Record<string, unknown>);
      if (keys.length === 1) {
        return String(keys[0] || '').trim();
      }
    }
    return '';
  })();

  return {
    ...raw,
    from_address_hash: normalizeByteArray((raw as any).from_address_hash) ?? (raw as any).from_address_hash,
    status: status as RecoveryAttemptStatus,
  };
}

// ===========================
// DEVICE LINKING TRANSACTION CALLS
// ===========================

/**
 * Execute device1's linking transactions (AddKey + Contract mapping)
 * This function signs and broadcasts both transactions required for device linking
 */
export async function executeDeviceLinkingContractCalls({
  context,
  device1AccountId,
  device2PublicKey,
  onEvent,
  confirmationConfigOverride,
  confirmerText,
}: {
  context: PasskeyManagerContext,
  device1AccountId: AccountId,
  device2PublicKey: string,
  onEvent?: (event: DeviceLinkingSSEEvent) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  confirmerText?: { title?: string; body?: string };
}): Promise<{
  addKeyTxResult: FinalExecutionOutcome;
}> {

  const signTransactions = () => context.webAuthnManager.signTransactionsWithActions({
    sessionId: (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
      ? `link-device-${crypto.randomUUID()}`
      : `link-device-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    rpcCall: {
      contractId: context.webAuthnManager.tatchiPasskeyConfigs.contractId,
      nearRpcUrl: context.webAuthnManager.tatchiPasskeyConfigs.nearRpcUrl,
      nearAccountId: device1AccountId
    },
    // Prefer threshold signing when available; fall back to local signing if the account
    // is not enrolled with threshold key material.
    signerMode: { mode: 'threshold-signer', behavior: 'fallback' },
    confirmationConfigOverride,
    title: confirmerText?.title,
    body: confirmerText?.body,
    transactions: [
      // Transaction 1: AddKey - Add Device2's key to Device1's account
      {
        receiverId: device1AccountId,
        actions: [{
          action_type: ActionType.AddKey,
          public_key: device2PublicKey,
          access_key: JSON.stringify({
            // NEAR-style AccessKey JSON shape, matching near-api-js:
            // { nonce: number, permission: { FullAccess: {} } }
            nonce: 0,
            permission: { FullAccess: {} },
          }),
        }],
      },
    ],
    onEvent: (progress) => {
      // Bridge all action progress events to the parent so the wallet iframe overlay
      // can expand during user confirmation in wallet-iframe mode.
      try { onEvent?.(progress as any); } catch { }
      // Keep existing mapping for device linking semantics; surface signing as a loading state
      if (progress.phase == ActionPhase.STEP_6_TRANSACTION_SIGNING_COMPLETE) {
        onEvent?.({
          step: 3,
          phase: DeviceLinkingPhase.STEP_3_AUTHORIZATION,
          status: DeviceLinkingStatus.PROGRESS,
          message: progress.message || 'Transaction signing in progress...'
        })
      }
    }
  });

  // Sign both transactions with one PRF authentication
  const signedTransactions = await signTransactions();

  if (!signedTransactions[0]?.signedTransaction) {
    throw new Error('AddKey transaction signing failed');
  }

  let addKeyTxResult: FinalExecutionOutcome;
  try {
    addKeyTxResult = await context.nearClient.sendTransaction(
      signedTransactions[0].signedTransaction,
      DEFAULT_WAIT_STATUS.linkDeviceAddKey
    );
  } catch (txError: any) {
    throw new Error(`Transaction broadcasting failed: ${txError.message}`);
  }

  onEvent?.({
    step: 7,
    phase: DeviceLinkingPhase.STEP_7_LINKING_COMPLETE,
    status: DeviceLinkingStatus.SUCCESS,
    message: `Device key added successfully!`
  });

  return {
    addKeyTxResult,
  };
}
