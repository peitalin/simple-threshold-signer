import type { Page } from '@playwright/test';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import {
  createInMemoryJwtSessionAdapter,
  installCreateAccountAndRegisterUserMock,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupThresholdE2ePage,
} from '../e2e/thresholdEd25519.testUtils';
import { createRelayRouter } from '@server/router/express-adaptor';
import { startExpressRouter } from '../relayer/helpers';

const DEFAULT_ECDSA_MASTER_SECRET_B64U = Buffer.from(new Uint8Array(32).fill(9)).toString('base64url');

export type ThresholdEcdsaTempoFlowOptions = {
  relayerUrl: string;
  signingKind?: 'tempoTransaction' | 'eip1559';
  accountId?: string;
  connectSession?: boolean;
  useBootstrapApi?: boolean;
  connectSessionTtlMs?: number;
  connectSessionRemainingUses?: number;
  waitBeforeSignMs?: number;
  keyRefUserId?: string;
  omitThresholdSessionFromKeyRef?: boolean;
  clearCachedThresholdSessionBeforeSign?: boolean;
};

export type ThresholdEcdsaTempoFlowResult = {
  ok: boolean;
  accountId: string;
  keygen?: {
    ok: boolean;
    relayerKeyId?: string;
    clientVerifyingShareB64u?: string;
    groupPublicKeyB64u?: string;
    relayerVerifyingShareB64u?: string;
    participantIds?: number[];
    code?: string;
    message?: string;
  };
  session?: {
    ok: boolean;
    sessionId?: string;
    jwt?: string;
    expiresAtMs?: number;
    remainingUses?: number;
    code?: string;
    message?: string;
  };
  signed?: {
    chain: 'tempo';
    kind: 'tempoTransaction';
    senderHashHex: string;
    rawTxHex: string;
  } | {
    chain: 'tempo';
    kind: 'eip1559';
    txHashHex: string;
    rawTxHex: string;
  };
  error?: string;
};

export async function setupThresholdEcdsaTempoHarness(page: Page): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
}> {
  await setupThresholdE2ePage(page);

  const keysOnChain = new Set<string>();
  const nonceByPublicKey = new Map<string, number>();

  const { service, threshold } = makeAuthServiceForThreshold(keysOnChain, {
    THRESHOLD_NODE_ROLE: 'coordinator',
    THRESHOLD_SECP256K1_MASTER_SECRET_B64U: DEFAULT_ECDSA_MASTER_SECRET_B64U,
  });
  await service.getRelayerAccount();

  const session = createInMemoryJwtSessionAdapter();
  const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
  const router = createRelayRouter(service, {
    corsOrigins: [frontendOrigin],
    threshold,
    session,
  });
  const server = await startExpressRouter(router);

  await installCreateAccountAndRegisterUserMock(page, {
    relayerBaseUrl: server.baseUrl,
    onNewPublicKey: (publicKey) => {
      keysOnChain.add(publicKey);
      nonceByPublicKey.set(publicKey, 0);
    },
  });
  await installFastNearRpcMock(page, {
    keysOnChain,
    nonceByPublicKey,
  });

  return {
    baseUrl: server.baseUrl,
    close: server.close,
  };
}

export async function runThresholdEcdsaTempoFlow(
  page: Page,
  options: ThresholdEcdsaTempoFlowOptions,
): Promise<ThresholdEcdsaTempoFlowResult> {
  return await page.evaluate(async (input) => {
    const sdkMod = await import('/sdk/esm/index.js');
    const indexedDbMod = await import('/sdk/esm/core/IndexedDBManager/index.js');

    const {
      TatchiPasskey,
      keygenThresholdEcdsaLite,
      connectThresholdEcdsaSessionLite,
    } = sdkMod as any;
    const { IndexedDBManager } = indexedDbMod as any;

    const accountId =
      (typeof input.accountId === 'string' && input.accountId.trim())
        ? input.accountId.trim()
        : `tempoecdsa${Date.now()}.w3a-v1.testnet`;

    const confirmationConfig = {
      uiMode: 'none' as const,
      behavior: 'skipClick' as const,
      autoProceedDelay: 0,
    };

    const pm = new TatchiPasskey({
      nearNetwork: 'testnet',
      nearRpcUrl: 'https://test.rpc.fastnear.com',
      contractId: 'web3-authn-v4.testnet',
      relayerAccount: 'web3-authn-v4.testnet',
      relayer: { url: input.relayerUrl },
      iframeWallet: {
        walletOrigin: '',
        walletServicePath: '/wallet-service',
        sdkBasePath: '/sdk',
        rpIdOverride: 'example.localhost',
      },
    });

    try {
      const registration = await pm.registerPasskeyInternal(accountId, {}, confirmationConfig);
      if (!registration?.success) {
        return {
          ok: false,
          accountId,
          error: String(registration?.error || 'registerPasskeyInternal failed'),
        };
      }

      let keygen: any;
      let session: any = undefined;
      let thresholdEcdsaKeyRef: any;

      const useBootstrapApi = input.useBootstrapApi !== false && input.connectSession !== false;
      if (useBootstrapApi) {
        try {
          const boot = await pm.bootstrapThresholdEcdsaSession({
            nearAccountId: accountId,
            options: {
              relayerUrl: input.relayerUrl,
              ...(typeof input.connectSessionTtlMs === 'number' ? { ttlMs: input.connectSessionTtlMs } : {}),
              ...(typeof input.connectSessionRemainingUses === 'number' ? { remainingUses: input.connectSessionRemainingUses } : {}),
            },
          });
          keygen = boot.keygen;
          session = boot.session;
          thresholdEcdsaKeyRef = { ...boot.thresholdEcdsaKeyRef };
        } catch (e: unknown) {
          return {
            ok: false,
            accountId,
            error: String(
              (e && typeof e === 'object' && 'message' in e)
                ? (e as { message?: unknown }).message
                : e || 'bootstrapThresholdEcdsaSession failed',
            ),
          };
        }
      } else {
        const ctx = pm.getContext();
        const webAuthnManager = ctx.webAuthnManager as any;

        keygen = await keygenThresholdEcdsaLite({
          indexedDB: IndexedDBManager,
          touchIdPrompt: webAuthnManager.touchIdPrompt,
          relayerUrl: input.relayerUrl,
          userId: accountId,
        });
        if (!keygen?.ok) {
          return {
            ok: false,
            accountId,
            keygen,
            error: String(keygen?.message || keygen?.code || 'threshold ecdsa keygen failed'),
          };
        }

        if (input.connectSession !== false) {
          session = await connectThresholdEcdsaSessionLite({
            indexedDB: IndexedDBManager,
            touchIdPrompt: webAuthnManager.touchIdPrompt,
            signerWorkerManager: webAuthnManager.signerWorkerManager,
            relayerUrl: input.relayerUrl,
            relayerKeyId: String(keygen.relayerKeyId || ''),
            userId: accountId,
            participantIds: keygen.participantIds,
            ...(typeof input.connectSessionTtlMs === 'number' ? { ttlMs: input.connectSessionTtlMs } : {}),
            ...(typeof input.connectSessionRemainingUses === 'number' ? { remainingUses: input.connectSessionRemainingUses } : {}),
          });
          if (!session?.ok) {
            return {
              ok: false,
              accountId,
              keygen,
              session,
              error: String(session?.message || session?.code || 'connectThresholdEcdsaSessionLite failed'),
            };
          }
        }

        thresholdEcdsaKeyRef = {
          type: 'threshold-ecdsa-secp256k1',
          userId: accountId,
          relayerUrl: input.relayerUrl,
          relayerKeyId: String(keygen.relayerKeyId || ''),
          clientVerifyingShareB64u: String(keygen.clientVerifyingShareB64u || ''),
          participantIds: Array.isArray(keygen.participantIds) ? keygen.participantIds : [1, 2],
          groupPublicKeyB64u: String(keygen.groupPublicKeyB64u || ''),
          relayerVerifyingShareB64u: String(keygen.relayerVerifyingShareB64u || ''),
        };

        if (session?.ok) {
          thresholdEcdsaKeyRef.thresholdSessionKind = 'jwt';
          thresholdEcdsaKeyRef.thresholdSessionJwt = session.jwt;
          thresholdEcdsaKeyRef.thresholdSessionId = session.sessionId;
        }
      }

      const waitBeforeSignMs = input.waitBeforeSignMs;
      if (typeof waitBeforeSignMs === 'number' && waitBeforeSignMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, Math.floor(waitBeforeSignMs)));
      }

      if (typeof input.keyRefUserId === 'string') {
        thresholdEcdsaKeyRef.userId = input.keyRefUserId;
      }

      if (input.omitThresholdSessionFromKeyRef) {
        delete thresholdEcdsaKeyRef.thresholdSessionKind;
        delete thresholdEcdsaKeyRef.thresholdSessionJwt;
        delete thresholdEcdsaKeyRef.thresholdSessionId;
      }

      if (input.clearCachedThresholdSessionBeforeSign) {
        try {
          const authSessionMod = await import('/sdk/esm/core/signing/schemes/threshold/session/thresholdEcdsaAuthSession.js');
          authSessionMod.clearAllCachedThresholdEcdsaAuthSessions?.();
        } catch {}
      }

      const request = input.signingKind === 'eip1559'
        ? {
            chain: 'tempo' as const,
            kind: 'eip1559' as const,
            senderSignatureAlgorithm: 'secp256k1' as const,
            tx: {
              chainId: 11155111n,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          }
        : {
            chain: 'tempo' as const,
            kind: 'tempoTransaction' as const,
            senderSignatureAlgorithm: 'secp256k1' as const,
            tx: {
              chainId: 42431n,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21_000n,
              calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
              accessList: [],
              nonceKey: 0n,
              nonce: 1n,
              validBefore: null,
              validAfter: null,
              feePayerSignature: { kind: 'none' as const },
              aaAuthorizationList: [],
            },
          };

      try {
        const signed = await pm.signTempoWithThresholdEcdsa({
          nearAccountId: accountId,
          request,
          thresholdEcdsaKeyRef,
          options: { confirmationConfig },
        });

        return {
          ok: true,
          accountId,
          keygen,
          session,
          signed,
        };
      } catch (e: unknown) {
        const message = String(
          (e && typeof e === 'object' && 'message' in e)
            ? (e as { message?: unknown }).message
            : e || 'signTempoWithThresholdEcdsa failed',
        );
        return {
          ok: false,
          accountId,
          keygen,
          session,
          error: message,
        };
      }
    } catch (e: unknown) {
      const message = String(
        (e && typeof e === 'object' && 'message' in e)
          ? (e as { message?: unknown }).message
          : e || 'threshold ecdsa flow failed',
      );
      return {
        ok: false,
        accountId,
        error: message,
      };
    }
  }, options);
}
