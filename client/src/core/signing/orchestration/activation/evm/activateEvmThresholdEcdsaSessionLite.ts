import {
  activateThresholdEcdsaSessionLite,
  type ActivateThresholdEcdsaSessionLiteDeps,
  type ActivateThresholdEcdsaSessionLiteRequest,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../thresholdEcdsa';

export async function activateEvmThresholdEcdsaSessionLite(
  deps: ActivateThresholdEcdsaSessionLiteDeps,
  args: ActivateThresholdEcdsaSessionLiteRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await activateThresholdEcdsaSessionLite(deps, args);
}
