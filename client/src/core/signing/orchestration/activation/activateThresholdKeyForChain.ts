import type {
  ThresholdKeyActivationAdapter,
  ThresholdKeyActivationAdaptersForChain,
  ThresholdKeyActivationChain,
} from './types';

export async function activateThresholdKeyForChain<
  Chain extends ThresholdKeyActivationChain,
  Request,
  Result,
>(args: {
  chain: Chain;
  request: Request;
  adapters: ThresholdKeyActivationAdaptersForChain<Chain, Request, Result>;
}): Promise<Result> {
  const adapter = args.adapters[args.chain];
  if (typeof adapter !== 'function') {
    throw new Error(`[activation] missing threshold-key activation adapter for chain: ${args.chain}`);
  }

  return await (
    adapter as ThresholdKeyActivationAdapter<Request, Result>
  )(args.request);
}
