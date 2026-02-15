import type { LocalNearSkV3Material } from '../../../../IndexedDBManager/passkeyNearKeysDB';

export function isRuntimeSigningLocalKeyMaterial(
  value: LocalNearSkV3Material | null | undefined,
): value is LocalNearSkV3Material {
  return !!value && value.usage !== 'export-only';
}

export function assertRuntimeSigningLocalKeyMaterial(args: {
  nearAccountId: string;
  localKeyMaterial: LocalNearSkV3Material | null | undefined;
}): void {
  if (!args.localKeyMaterial) return;
  if (args.localKeyMaterial.usage !== 'export-only') return;
  throw new Error(
    `[WebAuthnManager] local key material for account ${args.nearAccountId} is export-only and cannot be used for runtime signing`,
  );
}
