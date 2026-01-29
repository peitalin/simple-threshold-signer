import type {
  ParentToChildEnvelope,
  ParentToChildType,
  ChildToParentEnvelope,
  ProgressPayload,
  PMExecuteActionPayload,
} from '../shared/messages';
import type { TatchiPasskey } from '../../TatchiPasskey';
import { OFFLINE_EXPORT_FALLBACK, EXPORT_NEAR_KEYPAIR_CANCELLED, WALLET_UI_CLOSED } from '../../OfflineExport/messages';
import { errorMessage, isTouchIdCancellationError } from '../../../utils/errors';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
  SyncAccountHooksOptions,
} from '../../types/sdkSentEvents';
import type {
  LoginSession,
  RegistrationResult,
} from '../../types/tatchi';
import type { ConfirmationConfig } from '../../types/signer-worker';
import { toAccountId } from '../../types/accountIds';
import { SignedTransaction } from '../../NearClient';
import { isPlainSignedTransactionLike, extractBorshBytesFromPlainSignedTx, PlainSignedTransactionLike } from '@/utils/validation';
import type { ActionArgs } from '../../types';

type Req<T extends ParentToChildType> = Extract<ParentToChildEnvelope, { type: T }>;
type HandlerMap = Partial<{ [K in ParentToChildType]: (req: Extract<ParentToChildEnvelope, { type: K }>) => Promise<void> }>;

export interface HandlerDeps {
  getTatchiPasskey(): TatchiPasskey;
  post(msg: ChildToParentEnvelope): void;
  postProgress(requestId: string | undefined, payload: ProgressPayload): void;
  postToParent?(msg: unknown): void;
  respondIfCancelled(requestId: string | undefined): boolean;
}

export function createWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  const {
    getTatchiPasskey,
    post,
    postProgress,
    postToParent,
    respondIfCancelled,
  } = deps;

  const respondOk = (requestId: string | undefined): void => {
    post({ type: 'PM_RESULT', requestId, payload: { ok: true } });
  };

  const respondOkResult = (requestId: string | undefined, result: unknown): void => {
    post({ type: 'PM_RESULT', requestId, payload: { ok: true, result } });
  };

  const withProgress = <T extends object>(
    requestId: string | undefined,
    options?: T,
  ): T & { onEvent: (payload: ProgressPayload) => void } => {
    return {
      ...(options || {}),
      onEvent: (ev: ProgressPayload) => postProgress(requestId, ev),
    } as T & { onEvent: (payload: ProgressPayload) => void };
  };

  const normalizeSignedTransaction = (
    candidate: SignedTransaction | PlainSignedTransactionLike | undefined
  ): SignedTransaction | PlainSignedTransactionLike | undefined => {
    if (candidate && isPlainSignedTransactionLike(candidate)) {
      try {
        const borsh = extractBorshBytesFromPlainSignedTx(candidate);
        return SignedTransaction.fromPlain({
          transaction: candidate.transaction,
          signature: candidate.signature,
          borsh_bytes: borsh,
        });
      } catch {
        return candidate;
      }
    }
    return candidate;
  };

  const handlers = {
    PM_LOGIN: async (req: Req<'PM_LOGIN'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.loginAndCreateSession(
        nearAccountId,
        withProgress(req.requestId, options) as LoginHooksOptions,
      );
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_LOGOUT: async (req: Req<'PM_LOGOUT'>) => {
      const pm = getTatchiPasskey();
      await pm.logoutAndClearSession();
      respondOk(req.requestId);
    },

    PM_GET_LOGIN_SESSION: async (req: Req<'PM_GET_LOGIN_SESSION'>) => {
      const pm = getTatchiPasskey();
      const result: LoginSession = await pm.getLoginSession(req.payload?.nearAccountId);
      respondOkResult(req.requestId, result);
    },

    PM_REGISTER: async (req: Req<'PM_REGISTER'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, options, confirmationConfig } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;

      const hooksOptions = withProgress(req.requestId, options) as RegistrationHooksOptions;

      const result: RegistrationResult = !confirmationConfig
        ? await pm.registerPasskey(nearAccountId, hooksOptions)
        : await pm.registerPasskeyInternal(nearAccountId, hooksOptions,
            confirmationConfig as unknown as ConfirmationConfig);

      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_ENROLL_THRESHOLD_ED25519_KEY: async (req: Req<'PM_ENROLL_THRESHOLD_ED25519_KEY'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;

      const result = await pm.enrollThresholdEd25519Key(nearAccountId, options);
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_ROTATE_THRESHOLD_ED25519_KEY: async (req: Req<'PM_ROTATE_THRESHOLD_ED25519_KEY'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;

      const result = await pm.rotateThresholdEd25519Key(nearAccountId, options);
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SIGN_TXS_WITH_ACTIONS: async (req: Req<'PM_SIGN_TXS_WITH_ACTIONS'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, transactions, options } = req.payload!;

      const results = await pm.signTransactionsWithActions({
        nearAccountId,
        transactions: transactions,
        options: {
          ...withProgress(req.requestId, options || {}),
        } as SignTransactionHooksOptions,
      });

      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, results);
    },

    PM_SIGN_AND_SEND_TXS: async (req: Req<'PM_SIGN_AND_SEND_TXS'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, transactions, options } = req.payload || {};

      const results = await pm.signAndSendTransactions({
        nearAccountId: nearAccountId as string,
        transactions: transactions || [],
        options: {
          ...withProgress(req.requestId, options || {}),
        } as SignAndSendTransactionHooksOptions,
      });

      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, results);
    },

    PM_SEND_TRANSACTION: async (req: Req<'PM_SEND_TRANSACTION'>) => {
      const pm = getTatchiPasskey();
      const { signedTransaction, options } = req.payload || {};
      const st = normalizeSignedTransaction(signedTransaction);
      const result = await pm.sendTransaction({
        signedTransaction: st as SignedTransaction,
        options: {
          ...withProgress(req.requestId, options || {}),
        } as SendTransactionHooksOptions,
      });

      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_EXECUTE_ACTION: async (req: Req<'PM_EXECUTE_ACTION'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, receiverId, actionArgs, options } = (req.payload || ({} as Partial<PMExecuteActionPayload>));
      const result = await pm.executeAction({
        nearAccountId: nearAccountId as string,
        receiverId: receiverId as string,
        actionArgs: (actionArgs as ActionArgs | ActionArgs[])!,
        options: {
          ...withProgress(req.requestId, options || {}),
        } as ActionHooksOptions,
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SIGN_DELEGATE_ACTION: async (req: Req<'PM_SIGN_DELEGATE_ACTION'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, delegate, options } = req.payload!;
      const result = await pm.signDelegateAction({
        nearAccountId: nearAccountId,
        delegate,
        options: {
          ...withProgress(req.requestId, options || {}),
        } as DelegateActionHooksOptions,
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SIGN_NEP413: async (req: Req<'PM_SIGN_NEP413'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, params, options } = req.payload!;
      const result = await pm.signNEP413Message({
        nearAccountId,
        params,
        options: {
          ...withProgress(req.requestId, options || {}),
        } as SignNEP413HooksOptions,
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_EXPORT_NEAR_KEYPAIR_UI: async (req: Req<'PM_EXPORT_NEAR_KEYPAIR_UI'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, variant, theme } = req.payload!;
      if (pm.exportNearKeypairWithUI) {
        void pm.exportNearKeypairWithUI(nearAccountId, { variant, theme })
          .catch((err: unknown) => {
            // User cancelled TouchID/FaceID prompt: close UI and emit a cancellation hint
            // for parent UIs, without triggering offline-export fallback.
            if (isTouchIdCancellationError(err)) {
              postToParent?.({ type: EXPORT_NEAR_KEYPAIR_CANCELLED, nearAccountId });
              postToParent?.({ type: WALLET_UI_CLOSED });
              return;
            }
            postToParent?.({ type: OFFLINE_EXPORT_FALLBACK, error: errorMessage(err) });
            postToParent?.({ type: WALLET_UI_CLOSED });
          });
      }
      respondOk(req.requestId);
    },

    PM_GET_RECENT_LOGINS: async (req: Req<'PM_GET_RECENT_LOGINS'>) => {
      const pm = getTatchiPasskey();
      const result = await pm.getRecentLogins();
      respondOkResult(req.requestId, result);
    },

    PM_PREFETCH_BLOCKHEIGHT: async (req: Req<'PM_PREFETCH_BLOCKHEIGHT'>) => {
      const pm = getTatchiPasskey();
      await pm.prefetchBlockheight().catch(() => undefined);
      respondOk(req.requestId);
    },

    PM_SET_DERIVED_ADDRESS: async (req: Req<'PM_SET_DERIVED_ADDRESS'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, args } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      await pm.setDerivedAddress(nearAccountId, args);
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_GET_DERIVED_ADDRESS_RECORD: async (req: Req<'PM_GET_DERIVED_ADDRESS_RECORD'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, args } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.getDerivedAddressRecord(nearAccountId, args);
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_GET_DERIVED_ADDRESS: async (req: Req<'PM_GET_DERIVED_ADDRESS'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, args } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.getDerivedAddress(nearAccountId, args);
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_GET_RECOVERY_EMAILS: async (req: Req<'PM_GET_RECOVERY_EMAILS'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.getRecoveryEmails(nearAccountId);
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SET_RECOVERY_EMAILS: async (req: Req<'PM_SET_RECOVERY_EMAILS'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId, recoveryEmails, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.setRecoveryEmails(
        nearAccountId,
        Array.isArray(recoveryEmails) ? recoveryEmails : [],
        {
          ...withProgress(req.requestId, options || {}),
        } as ActionHooksOptions,
      );
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SYNC_ACCOUNT_FLOW: async (req: Req<'PM_SYNC_ACCOUNT_FLOW'>) => {
      const pm = getTatchiPasskey();
      const { accountId } = req.payload || {};
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.syncAccount({
        ...(accountId ? { accountId } : {}),
        options: {
          ...withProgress(req.requestId, {}),
        } as SyncAccountHooksOptions,
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_START_EMAIL_RECOVERY: async (req: Req<'PM_START_EMAIL_RECOVERY'>) => {
      const pm = getTatchiPasskey();
      const { accountId, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.startEmailRecovery({
        accountId,
        options: {
          ...withProgress(req.requestId, options || {}),
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_FINALIZE_EMAIL_RECOVERY: async (req: Req<'PM_FINALIZE_EMAIL_RECOVERY'>) => {
      const pm = getTatchiPasskey();
      const { accountId, nearPublicKey } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      await pm.finalizeEmailRecovery({
        accountId,
        ...(nearPublicKey ? { nearPublicKey } : {}),
        options: {
          ...withProgress(req.requestId, {}),
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_STOP_EMAIL_RECOVERY: async (req: Req<'PM_STOP_EMAIL_RECOVERY'>) => {
      const pm = getTatchiPasskey();
      const { accountId, nearPublicKey } = req.payload || {};
      if (respondIfCancelled(req.requestId)) return;
      await pm.cancelEmailRecovery({
        ...(accountId ? { accountId } : {}),
        ...(nearPublicKey ? { nearPublicKey } : {}),
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_START_DEVICE2_LINKING_FLOW: async (req: Req<'PM_START_DEVICE2_LINKING_FLOW'>) => {
      const pm = getTatchiPasskey();
      const { ui, cameraId, accountId, deviceNumber, localSignerEnabled, options } = req.payload || {};
      const accountIdValue = accountId ? toAccountId(accountId) : undefined;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.startDevice2LinkingFlow({
        ...(ui ? { ui } : {}),
        ...(cameraId ? { cameraId } : {}),
        ...(accountIdValue ? { accountId: accountIdValue } : {}),
        ...(typeof deviceNumber === 'number' ? { deviceNumber } : {}),
        ...(localSignerEnabled === false ? { localSignerEnabled: false } : {}),
        options: {
          ...withProgress(req.requestId, options || {}),
        },
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_STOP_DEVICE2_LINKING_FLOW: async (req: Req<'PM_STOP_DEVICE2_LINKING_FLOW'>) => {
      const pm = getTatchiPasskey();
      if (respondIfCancelled(req.requestId)) return;
      await pm.stopDevice2LinkingFlow();
      if (respondIfCancelled(req.requestId)) return;
      respondOk(req.requestId);
    },

    PM_LINK_DEVICE_WITH_SCANNED_QR_DATA: async (req: Req<'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA'>) => {
      const pm = getTatchiPasskey();
      const { qrData, fundingAmount, options } = req.payload!;
      if (respondIfCancelled(req.requestId)) return;
      const result = await pm.linkDeviceWithScannedQRData(qrData, {
        fundingAmount: String(fundingAmount || ''),
        ...withProgress(req.requestId, options || {}),
      });
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

    PM_SET_CONFIRM_BEHAVIOR: async (req: Req<'PM_SET_CONFIRM_BEHAVIOR'>) => {
      const pm = getTatchiPasskey();
      const { behavior } = req.payload!;
      pm.setConfirmBehavior(behavior);
      respondOk(req.requestId);
    },

    PM_SET_CONFIRMATION_CONFIG: async (req: Req<'PM_SET_CONFIRMATION_CONFIG'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId } = (req.payload || {});
      const incoming = (req.payload?.config || {}) as Record<string, unknown>;
      let patch: Record<string, unknown> = { ...incoming };
      if (nearAccountId) {
        await pm.getLoginSession(nearAccountId)
          .then(({ login }) => {
            const existing = (login?.userData?.preferences?.confirmationConfig || {}) as Record<string, unknown>;
            patch = { ...existing, ...incoming };
          })
          .catch(() => undefined);
      }
      const base: ConfirmationConfig = pm.getConfirmationConfig();
      pm.setConfirmationConfig({ ...base, ...patch });
      respondOk(req.requestId);
    },

    PM_GET_CONFIRMATION_CONFIG: async (req: Req<'PM_GET_CONFIRMATION_CONFIG'>) => {
      const pm = getTatchiPasskey();
      const result = pm.getConfirmationConfig();
      respondOkResult(req.requestId, result);
    },

    PM_SET_SIGNER_MODE: async (req: Req<'PM_SET_SIGNER_MODE'>) => {
      const pm = getTatchiPasskey();
      const { signerMode } = req.payload!;
      try {
        pm.setSignerMode(signerMode);
      } catch {}
      respondOk(req.requestId);
    },

    PM_GET_SIGNER_MODE: async (req: Req<'PM_GET_SIGNER_MODE'>) => {
      const pm = getTatchiPasskey();
      const result = pm.getSignerMode();
      respondOkResult(req.requestId, result);
    },

    PM_SET_THEME: async (req: Req<'PM_SET_THEME'>) => {
      const pm = getTatchiPasskey();
      const { theme } = req.payload!;
      try { pm.setTheme(theme); } catch {}
      try {
        if (theme === 'light' || theme === 'dark') {
          document.documentElement.setAttribute('data-w3a-theme', theme);
        }
      } catch {}
      respondOk(req.requestId);
    },

    PM_HAS_PASSKEY: async (req: Req<'PM_HAS_PASSKEY'>) => {
      const pm = getTatchiPasskey();
      const { nearAccountId } = req.payload!;
      // Soft probe to warm caches in some environments (optional)
      const ctx = pm.getContext();
      const web = ctx?.webAuthnManager;
      if (web) {
        await web.getLastUser().catch(() => undefined);
        await web.getAuthenticatorsByUser(toAccountId(nearAccountId)).catch(() => undefined);
      }
      const result = await pm.hasPasskeyCredential(toAccountId(nearAccountId));
      respondOkResult(req.requestId, result);
    },

    PM_VIEW_ACCESS_KEYS: async (req: Req<'PM_VIEW_ACCESS_KEYS'>) => {
      const pm = getTatchiPasskey();
      const { accountId } = req.payload!;
      const result = await pm.viewAccessKeyList(accountId);
      respondOkResult(req.requestId, result);
    },

    PM_DELETE_DEVICE_KEY: async (req: Req<'PM_DELETE_DEVICE_KEY'>) => {
      const pm = getTatchiPasskey();
      const { accountId, publicKeyToDelete, options } = req.payload!;
      const result = await pm.deleteDeviceKey(accountId, publicKeyToDelete, {
        ...withProgress(req.requestId, options || {}),
      } as ActionHooksOptions);
      if (respondIfCancelled(req.requestId)) return;
      respondOkResult(req.requestId, result);
    },

  } satisfies HandlerMap;

  return handlers;
}
