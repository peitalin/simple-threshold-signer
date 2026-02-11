/**
 * NEAR-specific utility helpers.
 *
 * Keep chain-specific parsing and validation logic here so generic utility
 * modules (`validation`, `errors`, `encoders`, etc.) stay chain-agnostic.
 */

export interface NearAccountValidationOptions {
  /** Restrict to specific suffixes (e.g., ['testnet', 'near']) */
  allowedSuffixes?: string[];
  /** Require Top-level domains with exactly 2 parts (username.suffix) instead of allowing subdomains */
  requireTopLevelDomain?: boolean;
}

/**
 * Ensure a key string has the NEAR Ed25519 prefix (`ed25519:`).
 *
 * - Accepts either `ed25519:<base58>` or a bare `<base58>` string.
 * - Canonicalizes `ED25519:` -> `ed25519:`.
 * - If a different prefix is present (e.g. `secp256k1:`), returns the input unchanged.
 */
export function ensureEd25519Prefix(value: string): string {
  const raw = String(value ?? '').trim();
  if (!raw) return '';

  if (/^[a-z0-9_]+:/i.test(raw)) {
    if (/^ed25519:/i.test(raw)) {
      return `ed25519:${raw.replace(/^ed25519:/i, '')}`;
    }
    return raw;
  }

  return `ed25519:${raw}`;
}

/**
 * Validate NEAR account ID format with optional suffix restrictions.
 */
export function validateNearAccountId(
  nearAccountId: string,
  options: NearAccountValidationOptions = {
    allowedSuffixes: ['testnet', 'near'],
    requireTopLevelDomain: false
  }
): { valid: boolean; error?: string } {
  if (!nearAccountId || typeof nearAccountId !== 'string') {
    return { valid: false, error: 'Account ID must be a non-empty string' };
  }

  const parts = nearAccountId.split('.');
  if (parts.length < 2) {
    return { valid: false, error: 'Account ID must contain at least one dot (e.g., username.testnet)' };
  }

  // Check for exact two parts requirement (e.g., server registration)
  if (options.requireTopLevelDomain && parts.length !== 2) {
    const suffixList = options.allowedSuffixes?.join(', ') || 'valid suffixes';
    return {
      valid: false,
      error: `Invalid NEAR account ID format. Expected format: <username>.<suffix> where suffix is one of: ${suffixList}`
    };
  }

  const username = parts[0];
  const suffix = parts[parts.length - 1]; // Last part for suffix checking
  const domain = parts.slice(1).join('.');

  if (!username || username.length === 0) {
    return { valid: false, error: 'Username part cannot be empty' };
  }

  if (!/^[a-z0-9_\-]+$/.test(username)) {
    return { valid: false, error: 'Username can only contain lowercase letters, numbers, underscores, and hyphens' };
  }

  if (!domain || domain.length === 0) {
    return { valid: false, error: 'Domain part cannot be empty' };
  }

  if (options.allowedSuffixes && options.allowedSuffixes.length > 0) {
    const matchesAnySuffix = options.allowedSuffixes.some((allowedSuffix) => {
      if (!allowedSuffix.includes('.')) {
        return suffix === allowedSuffix;
      }
      return nearAccountId.endsWith(`.${allowedSuffix}`);
    });

    if (!matchesAnySuffix) {
      return {
        valid: false,
        error: `Invalid NEAR account ID suffix. Expected account to end with one of: ${options.allowedSuffixes.join(', ')}`
      };
    }
  }

  return { valid: true };
}

/**
 * Lightweight NEAR account ID validation used by server-side helpers.
 * - length: 2..64
 * - chars: lowercase letters, digits, `_`, `.`, `-`
 */
export function isValidAccountId(accountId: unknown): accountId is string {
  if (typeof accountId !== 'string') return false;
  if (!accountId || accountId.length < 2 || accountId.length > 64) return false;
  return /^[a-z0-9_.-]+$/.test(accountId);
}

/**
 * Format a NEAR JSON-RPC error into a concise, human-friendly message while
 * preserving the original error payload on `details`.
 *
 * The function is defensive and only relies on structural checks. It does not
 * require concrete NEAR types to avoid tight coupling with providers.
 */
export function formatNearRpcError(
  operationName: string,
  rpc: { error?: { code?: number; name?: string; message?: string; data?: unknown } }
): { message: string; code?: number; name?: string; details?: unknown } {
  const err = rpc?.error || {};
  const details = err.data as unknown;

  const code = typeof err.code === 'number' ? err.code : undefined;
  const name = typeof err.name === 'string' ? err.name : undefined;
  const generic = typeof err.message === 'string'
    ? err.message
    : (details && typeof (details as { message?: unknown }).message === 'string'
        ? (details as { message: string }).message
        : 'RPC error');

  const firstKey = (o: unknown): string | undefined => {
    if (!o || typeof o !== 'object') return undefined;
    const keys = Object.keys(o as Record<string, unknown>);
    return keys.length ? keys[0] : undefined;
  };

  const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

  const d = details as Record<string, unknown> | undefined;
  const txExec = isObj(d) ? d.TxExecutionError : undefined;
  if (isObj(txExec)) {
    let node: Record<string, unknown> | undefined = txExec;
    const path: string[] = ['TxExecutionError'];
    let depth = 0;
    while (node && depth < 5 && isObj(node)) {
      const k = firstKey(node);
      if (!k) break;
      const nextNode: unknown = (node as Record<string, unknown>)[k as string];
      path.push(k);
      node = isObj(nextNode) ? (nextNode as Record<string, unknown>) : undefined;
      depth++;
    }

    const actionError = (isObj(txExec) && isObj(txExec.ActionError)) ? txExec.ActionError as Record<string, unknown> : undefined;
    const idx = (isObj(actionError) && typeof actionError.index === 'number') ? ` at action ${actionError.index}` : '';

    const payload = isObj(node) ? node : undefined;
    const suffix = payload && Object.keys(payload).length ? `: ${JSON.stringify(payload)}` : '';
    const prefix = [name, typeof code === 'number' ? `code ${code}` : undefined].filter(Boolean).join(' ');
    const kindPath = path.join('.');
    const message = [prefix, `${operationName} failed${idx} (${kindPath}${suffix})`].filter(Boolean).join(' - ');
    return { message, code, name, details };
  }

  const prefix = [name, typeof code === 'number' ? `code ${code}` : undefined].filter(Boolean).join(' ');
  const dataStr = isObj(details) ? ` Details: ${JSON.stringify(details)}` : '';
  const message = [prefix, `${operationName} RPC error: ${generic}${dataStr}`].filter(Boolean).join(' - ');
  return { message, code, name, details };
}

/**
 * Extract a short NEAR error label for UI display, e.g.:
 *   "InvalidTxError: UnsuitableStakingKey"
 * Falls back to undefined when structure is not recognized.
 */
export function getNearShortErrorMessage(error: unknown): string | undefined {
  try {
    const err = error as { details?: unknown; message?: string };
    const details = err?.details as Record<string, unknown> | undefined;
    const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
    if (!isObj(details)) return undefined;

    const txExec = details.TxExecutionError as unknown;
    if (isObj(txExec)) {
      if (isObj(txExec.InvalidTxError)) {
        const inv = txExec.InvalidTxError as Record<string, unknown>;
        if (isObj(inv.ActionsValidation)) {
          const kind = Object.keys(inv.ActionsValidation)[0];
          if (kind) return `InvalidTxError: ${kind}`;
        }
        const first = Object.keys(inv)[0];
        if (first) return `InvalidTxError: ${first}`;
        return 'InvalidTxError';
      }
      if (isObj(txExec.ActionError)) {
        const ae = txExec.ActionError as Record<string, unknown>;
        const kindObj = isObj(ae.kind) ? (ae.kind as Record<string, unknown>) : undefined;
        const kind = kindObj ? Object.keys(kindObj)[0] : undefined;
        if (kind) return `ActionError: ${kind}`;
        return 'ActionError';
      }
    }

    const failure = details.Failure as unknown;
    if (isObj(failure)) {
      if (isObj(failure.InvalidTxError)) {
        const inv = failure.InvalidTxError as Record<string, unknown>;
        if (isObj(inv.ActionsValidation)) {
          const kind = Object.keys(inv.ActionsValidation)[0];
          if (kind) return `InvalidTxError: ${kind}`;
        }
        const first = Object.keys(inv)[0];
        if (first) return `InvalidTxError: ${first}`;
        return 'InvalidTxError';
      }
      if (isObj(failure.ActionError)) {
        const ae = failure.ActionError as Record<string, unknown>;
        const kindObj = isObj(ae.kind) ? (ae.kind as Record<string, unknown>) : undefined;
        const kind = kindObj ? Object.keys(kindObj)[0] : undefined;
        if (kind) return `ActionError: ${kind}`;
        return 'ActionError';
      }
    }

    return undefined;
  } catch {
    return undefined;
  }
}
