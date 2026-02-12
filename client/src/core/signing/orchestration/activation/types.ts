export type ThresholdKeyActivationChain = 'near' | 'evm' | 'tempo';

export type ThresholdKeyActivationAdapter<Request = any, Result = any> = (
  request: Request,
) => Promise<Result>;

export type ThresholdKeyActivationAdapterMap = Partial<
  Record<ThresholdKeyActivationChain, ThresholdKeyActivationAdapter<any, any>>
>;

export type ThresholdKeyActivationAdaptersForChain<
  Chain extends ThresholdKeyActivationChain,
  Request,
  Result,
> = ThresholdKeyActivationAdapterMap & Record<Chain, ThresholdKeyActivationAdapter<Request, Result>>;
