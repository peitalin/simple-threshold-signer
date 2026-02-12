import {
  activateThresholdEcdsaSessionLite,
  type ActivateThresholdEcdsaSessionLiteDeps,
  type ActivateThresholdEcdsaSessionLiteRequest,
  type ThresholdEcdsaSessionBootstrapResult,
} from '../thresholdEcdsa';

export async function activateTempoThresholdEcdsaSessionLite(
  deps: ActivateThresholdEcdsaSessionLiteDeps,
  args: ActivateThresholdEcdsaSessionLiteRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  return await activateThresholdEcdsaSessionLite(deps, args);
}
