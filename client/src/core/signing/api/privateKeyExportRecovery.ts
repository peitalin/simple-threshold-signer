import type { UnifiedIndexedDBManager } from '../../IndexedDBManager';
import { toAccountId, type AccountId } from '../../types/accountIds';
import type { ThemeName } from '../../types/tatchi';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../../types';
import {
  SecureConfirmationType,
  type ExportPrivateKeyDisplayEntry,
  type SecureConfirmRequest,
} from '../secureConfirm/confirmTxFlow/types';
import { runSecureConfirm } from '../secureConfirm/secureConfirmBridge';
import type { SecureConfirmWorkerManager } from '../secureConfirm/manager';
import { getLastLoggedInDeviceNumber } from '../webauthn/device/getDeviceNumber';
import { getPrfResultsFromCredential } from '../webauthn/credentials/credentialExtensions';
import type { SignerWorkerManagerContext } from '../workers/signerWorkerManager';

type ExportScheme = 'ed25519' | 'secp256k1';

type RecoverKeypairResult = {
  publicKey: string;
  encryptedPrivateKey: string;
  chacha20NonceB64u: string;
  accountIdHint?: string;
  wrapKeySalt: string;
  stored?: boolean;
};

export type PrivateKeyExportRecoveryDeps = {
  indexedDB: UnifiedIndexedDBManager;
  secureConfirmWorkerManager: Pick<
    SecureConfirmWorkerManager,
    'getContext'
  >;
  getTheme: () => ThemeName;
  signingKeyOps: {
    exportNearKeypairUi: (args: {
      nearAccountId: AccountId;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      sessionId: string;
      prfFirstB64u: string;
      wrapKeySalt: string;
    }) => Promise<void>;
    decryptPrivateKeyWithPrf: (args: {
      nearAccountId: AccountId;
      authenticators: any[];
      sessionId: string;
      prfFirstB64u?: string;
      wrapKeySalt?: string;
      encryptedPrivateKeyData?: string;
      encryptedPrivateKeyChacha20NonceB64u?: string;
      deviceNumber?: number;
    }) => Promise<{
      decryptedPrivateKey: string;
      nearAccountId: AccountId;
    }>;
    recoverKeypairFromPasskey: (args: {
      credential: WebAuthnAuthenticationCredential;
      accountIdHint?: string;
      sessionId: string;
    }) => Promise<RecoverKeypairResult>;
  };
  deriveNearKeypairFromCredentialViaWorker: (args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId;
  }) => Promise<{ publicKey: string; privateKey: string }>;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  createSessionId: (prefix: string) => string;
};

function requirePrfB64uFromCredential(
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
  output: 'first' | 'second',
): string {
  const value = getPrfResultsFromCredential(credential)[output];
  if (!value) {
    throw new Error(`Missing PRF.${output} output from credential (requires a PRF-enabled passkey)`);
  }
  return value;
}

export async function exportNearKeypairWithUIWorkerDriven(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options?: { variant?: 'drawer' | 'modal'; theme?: 'dark' | 'light' };
  },
): Promise<void> {
  const resolvedTheme = args.options?.theme ?? deps.getTheme();

  const accountId = toAccountId(args.nearAccountId);
  const deviceNumber = await getLastLoggedInDeviceNumber(accountId, deps.indexedDB.clientDB).catch(
    () => null as number | null,
  );
  if (deviceNumber == null) {
    throw new Error(`No deviceNumber found for account ${accountId} (export/decrypt)`);
  }
  const userForAccount = await deps.indexedDB.clientDB
    .getNearAccountProjection(accountId, deviceNumber)
    .catch(() => null);

  const [keyMaterial, thresholdKeyMaterial] = await Promise.all([
    deps.indexedDB.getNearLocalKeyMaterialV2First(accountId, deviceNumber).catch(() => null),
    deps.indexedDB.getNearThresholdKeyMaterialV2First(accountId, deviceNumber).catch(
      () => null,
    ),
  ]);

  const wrapKeySalt = String(keyMaterial?.wrapKeySalt || '').trim();
  if (keyMaterial && wrapKeySalt) {
    const publicKey = String(userForAccount?.clientNearPublicKey || '').trim();
    if (!publicKey) {
      throw new Error(`Missing public key for account ${accountId}; please login again.`);
    }

    const requestId = deps.createSessionId('decrypt');
    const decision = await runSecureConfirm(deps.secureConfirmWorkerManager.getContext(), {
      requestId,
      type: SecureConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: 'Decrypt Private Key',
        accountId: String(accountId),
        publicKey,
        warning: 'Authenticate with your passkey to decrypt your local key material.',
      },
      payload: {
        nearAccountId: String(accountId),
        publicKey,
      },
      intentDigest: `decrypt:${accountId}:${deviceNumber}`,
    } satisfies SecureConfirmRequest);

    if (!decision?.confirmed) {
      throw new Error(decision?.error || 'User rejected decrypt request');
    }
    if (!decision.credential) {
      throw new Error('Missing WebAuthn credential for decrypt request');
    }

    const prfFirstB64u = requirePrfB64uFromCredential(
      decision.credential as WebAuthnAuthenticationCredential,
      'first',
    );
    await deps.signingKeyOps.exportNearKeypairUi({
      nearAccountId: accountId,
      variant: args.options?.variant,
      theme: resolvedTheme,
      sessionId: requestId,
      prfFirstB64u,
      wrapKeySalt,
    });
    return;
  }

  if (thresholdKeyMaterial) {
    const publicKeyHint = String(
      userForAccount?.clientNearPublicKey || thresholdKeyMaterial.publicKey || '',
    ).trim();

    const requestId = deps.createSessionId('export');
    const decision = await runSecureConfirm(deps.secureConfirmWorkerManager.getContext(), {
      requestId,
      type: SecureConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: 'Export Private Key',
        accountId: String(accountId),
        publicKey: publicKeyHint || '(derived from passkey)',
        warning: 'Authenticate with your passkey to derive your backup key (escape hatch).',
      },
      payload: {
        nearAccountId: String(accountId),
        publicKey: publicKeyHint,
      },
      intentDigest: `export-backup:${accountId}:${deviceNumber}`,
    } satisfies SecureConfirmRequest);

    if (!decision?.confirmed) {
      throw new Error(decision?.error || 'User rejected export request');
    }
    if (!decision.credential) {
      throw new Error('Missing WebAuthn credential for export request');
    }

    const derived = await deps.deriveNearKeypairFromCredentialViaWorker({
      credential: decision.credential as WebAuthnAuthenticationCredential,
      nearAccountId: accountId,
    });
    await runSecureConfirm(deps.secureConfirmWorkerManager.getContext(), {
      requestId: `${requestId}-show`,
      type: SecureConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: String(accountId),
        publicKey: derived.publicKey,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        nearAccountId: String(accountId),
        publicKey: derived.publicKey,
        privateKey: derived.privateKey,
        variant: args.options?.variant,
        theme: resolvedTheme,
      },
      intentDigest: `export-backup:${accountId}:${deviceNumber}`,
    } satisfies SecureConfirmRequest);
    return;
  }

  throw new Error(`No key material found for account ${accountId} device ${deviceNumber}`);
}

export async function exportNearKeypairWithUI(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options?: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<{ accountId: string; publicKey: string; privateKey: string }> {
  await exportNearKeypairWithUIWorkerDriven(deps, args);
  const accountId = toAccountId(args.nearAccountId);
  const deviceNumber = await getLastLoggedInDeviceNumber(accountId, deps.indexedDB.clientDB).catch(
    () => null as number | null,
  );
  const userData =
    deviceNumber != null
      ? await deps.indexedDB.clientDB.getNearAccountProjection(accountId, deviceNumber).catch(() => null)
      : null;
  return {
    accountId: String(args.nearAccountId),
    publicKey: userData?.clientNearPublicKey ?? '',
    privateKey: '',
  };
}

export async function exportPrivateKeysWithUIWorkerDriven(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options?: {
      schemes?: ExportScheme[];
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<void> {
  const resolvedTheme = args.options?.theme ?? deps.getTheme();
  const requestedSchemes =
    Array.isArray(args.options?.schemes) && args.options?.schemes.length
      ? args.options.schemes
      : (['ed25519', 'secp256k1'] as const);
  const schemes = Array.from(new Set(requestedSchemes)).filter(
    (scheme): scheme is ExportScheme => scheme === 'ed25519' || scheme === 'secp256k1',
  );
  if (!schemes.length) throw new Error('No export schemes requested');

  const accountId = toAccountId(args.nearAccountId);
  const deviceNumber = await getLastLoggedInDeviceNumber(accountId, deps.indexedDB.clientDB).catch(
    () => null as number | null,
  );
  if (deviceNumber == null) {
    throw new Error(`No deviceNumber found for account ${accountId} (export/decrypt)`);
  }
  const userForAccount = await deps.indexedDB.clientDB
    .getNearAccountProjection(accountId, deviceNumber)
    .catch(() => null);

  const [keyMaterial, thresholdKeyMaterial] = await Promise.all([
    deps.indexedDB.getNearLocalKeyMaterialV2First(accountId, deviceNumber).catch(() => null),
    deps.indexedDB.getNearThresholdKeyMaterialV2First(accountId, deviceNumber).catch(
      () => null,
    ),
  ]);
  if (!keyMaterial && !thresholdKeyMaterial) {
    throw new Error(`No key material found for account ${accountId} device ${deviceNumber}`);
  }

  const publicKeyHint = String(
    userForAccount?.clientNearPublicKey ||
      keyMaterial?.publicKey ||
      thresholdKeyMaterial?.publicKey ||
      '',
  ).trim();

  const requestId = deps.createSessionId('export-keys');
  const decision = await runSecureConfirm(deps.secureConfirmWorkerManager.getContext(), {
    requestId,
    type: SecureConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
    summary: {
      operation: 'Export Private Key',
      accountId: String(accountId),
      publicKey: publicKeyHint || '(derived from passkey)',
      warning: 'Authenticate with your passkey to prepare export keys.',
    },
    payload: {
      nearAccountId: String(accountId),
      publicKey: publicKeyHint,
    },
    intentDigest: `export-keys:${accountId}:${deviceNumber}`,
  } satisfies SecureConfirmRequest);

  if (!decision?.confirmed) {
    throw new Error(decision?.error || 'User rejected export request');
  }
  if (!decision.credential) {
    throw new Error('Missing WebAuthn credential for export request');
  }

  const credential = decision.credential as WebAuthnAuthenticationCredential;
  const exportKeys: ExportPrivateKeyDisplayEntry[] = [];

  if (schemes.includes('ed25519')) {
    const localWrapKeySalt = String(keyMaterial?.wrapKeySalt || '').trim();
    if (keyMaterial && localWrapKeySalt) {
      const prfFirstB64u = requirePrfB64uFromCredential(credential, 'first');
      const decrypted = await deps.signingKeyOps.decryptPrivateKeyWithPrf({
        nearAccountId: accountId,
        authenticators: [],
        sessionId: `${requestId}:ed25519`,
        prfFirstB64u,
        wrapKeySalt: localWrapKeySalt,
      });
      exportKeys.push({
        scheme: 'ed25519',
        label: 'NEAR Ed25519',
        publicKey: String(keyMaterial.publicKey || publicKeyHint || '').trim(),
        privateKey: String(decrypted.decryptedPrivateKey || '').trim(),
      });
    } else {
      const derived = await deps.deriveNearKeypairFromCredentialViaWorker({
        credential,
        nearAccountId: accountId,
      });
      exportKeys.push({
        scheme: 'ed25519',
        label: 'NEAR Ed25519',
        publicKey: derived.publicKey,
        privateKey: derived.privateKey,
      });
    }
  }

  if (schemes.includes('secp256k1')) {
    const prfSecondB64u = requirePrfB64uFromCredential(credential, 'second');
    const { deriveSecp256k1KeypairFromPrfSecondWasm } = await import(
      '../chainAdaptors/evm/ethSignerWasm'
    );
    const derived = await deriveSecp256k1KeypairFromPrfSecondWasm({
      prfSecondB64u,
      nearAccountId: String(accountId),
      workerCtx: deps.getSignerWorkerContext(),
    });
    exportKeys.push({
      scheme: 'secp256k1',
      label: 'EVM secp256k1',
      publicKey: derived.publicKeyHex,
      privateKey: derived.privateKeyHex,
      address: derived.ethereumAddress,
    });
  }

  if (!exportKeys.length) {
    throw new Error('No exportable keys were produced');
  }

  const first = exportKeys[0]!;
  await runSecureConfirm(deps.secureConfirmWorkerManager.getContext(), {
    requestId: `${requestId}-show`,
    type: SecureConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
    summary: {
      operation: 'Export Private Key',
      accountId: String(accountId),
      publicKey: first.publicKey,
      warning: 'Anyone with your private key can fully control your account. Never share it.',
    },
    payload: {
      nearAccountId: String(accountId),
      publicKey: first.publicKey,
      privateKey: first.privateKey,
      keys: exportKeys,
      variant: args.options?.variant,
      theme: resolvedTheme,
    },
    intentDigest: `export-keys:${accountId}:${deviceNumber}`,
  } satisfies SecureConfirmRequest);
}

export async function exportPrivateKeysWithUI(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options?: {
      schemes?: ExportScheme[];
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<{ accountId: string; exportedSchemes: ExportScheme[] }> {
  const requestedSchemes =
    Array.isArray(args.options?.schemes) && args.options?.schemes.length
      ? args.options.schemes
      : (['ed25519', 'secp256k1'] as const);
  const exportedSchemes = Array.from(new Set(requestedSchemes)).filter(
    (scheme): scheme is ExportScheme => scheme === 'ed25519' || scheme === 'secp256k1',
  );
  await exportPrivateKeysWithUIWorkerDriven(deps, args);
  return {
    accountId: String(args.nearAccountId),
    exportedSchemes,
  };
}

export async function recoverKeypairFromPasskey(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    authenticationCredential: WebAuthnAuthenticationCredential;
    accountIdHint?: string;
  },
): Promise<RecoverKeypairResult> {
  try {
    if (!args.authenticationCredential) {
      throw new Error(
        'Authentication credential required for account recovery. '
          + 'Use an existing credential with dual PRF outputs to re-derive the same NEAR keypair.',
      );
    }

    const prfResults = args.authenticationCredential.clientExtensionResults?.prf?.results;
    if (!prfResults?.first || !prfResults?.second) {
      throw new Error(
        'Dual PRF outputs required for account recovery - both AES and Ed25519 PRF outputs must be available',
      );
    }

    const sessionId = deps.createSessionId('recover');
    return await deps.signingKeyOps.recoverKeypairFromPasskey({
      credential: args.authenticationCredential,
      accountIdHint: args.accountIdHint,
      sessionId,
    });
  } catch (error: any) {
    // eslint-disable-next-line no-console
    console.error('WebAuthnManager: Deterministic keypair derivation error:', error);
    throw new Error(`Deterministic keypair derivation failed: ${error.message}`);
  }
}
