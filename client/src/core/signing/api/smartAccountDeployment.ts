import type { TatchiConfigs } from '../../types/tatchi';
import type {
  SmartAccountDeployerInput,
  SmartAccountDeployerResult,
} from '../orchestration/deployment/ensureSmartAccountDeployed';

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function resolveSmartAccountDeployEndpoint(configs: TatchiConfigs): string {
  const relayerUrl = String(configs.relayer?.url || '').trim();
  if (!relayerUrl) {
    throw new Error('[deployment] missing relayer url (configs.relayer.url)');
  }
  const routeRaw = String(configs.relayer?.smartAccountDeployRoute || '/smart-account/deploy').trim();
  const route = routeRaw.startsWith('/') ? routeRaw : `/${routeRaw}`;
  return `${relayerUrl.replace(/\/$/, '')}${route}`;
}

export function resolveSmartAccountDeploymentMode(configs: TatchiConfigs): 'observe' | 'enforce' {
  return configs.relayer?.smartAccountDeploymentMode === 'enforce' ? 'enforce' : 'observe';
}

export function resolveSmartAccountDeploymentMaxAttempts(configs: TatchiConfigs): number {
  const candidate = configs.relayer?.smartAccountDeploymentMaxAttempts;
  if (typeof candidate !== 'number' || !Number.isFinite(candidate)) return 2;
  const rounded = Math.trunc(candidate);
  if (rounded < 1) return 1;
  if (rounded > 5) return 5;
  return rounded;
}

export async function deploySmartAccountForChain(
  configs: TatchiConfigs,
  input: SmartAccountDeployerInput,
): Promise<SmartAccountDeployerResult> {
  const endpoint = resolveSmartAccountDeployEndpoint(configs);
  const body = {
    nearAccountId: String(input.nearAccountId || '').trim(),
    chain: input.chain,
    chainId: String(input.chainId || '').trim(),
    accountAddress: String(input.account.accountAddress || '').trim(),
    accountModel: String(input.account.accountModel || '').trim(),
    counterfactualAddress: String(input.account.counterfactualAddress || '').trim(),
    ...(input.account.factory ? { factory: String(input.account.factory).trim() } : {}),
    ...(input.account.entryPoint ? { entryPoint: String(input.account.entryPoint).trim() } : {}),
    ...(input.account.salt ? { salt: String(input.account.salt).trim() } : {}),
  };

  let json: Record<string, unknown> | null = null;
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    json = await response.json().catch(() => null) as Record<string, unknown> | null;

    const resultOk =
      (json && json.ok === true)
      || (json && json.success === true)
      || (!json && response.ok);
    if (!response.ok || !resultOk) {
      const code = normalizeOptionalString(
        json?.code || json?.errorCode || json?.statusCode || `http_${response.status}`,
      );
      const message = normalizeOptionalString(
        json?.message || json?.error || response.statusText || 'deployment failed',
      ) || 'deployment failed';
      return {
        ok: false,
        ...(code ? { code } : {}),
        message,
      };
    }

    const deploymentTxHash = normalizeOptionalString(
      json?.deploymentTxHash || json?.txHash || json?.transactionHash || json?.hash,
    );
    return {
      ok: true,
      ...(deploymentTxHash ? { deploymentTxHash } : {}),
    };
  } catch (error: unknown) {
    const message = normalizeOptionalString((error as { message?: unknown })?.message || error)
      || 'deployment request failed';
    return {
      ok: false,
      code: 'request_failed',
      message,
    };
  }
}
