import { executeSigningIntent } from './executeSigningIntent';
import type { ChainAdapter, SigningEngineMap } from './types';

export async function signWithIntent<
  Input,
  Result,
  Request extends { algorithm: string },
  Signed,
  ResolvedSignInput extends { signReq: Request; keyRef: unknown },
>(args: {
  adapter: ChainAdapter<Input, unknown, Result, Request, Signed>;
  request: Input;
  engines: SigningEngineMap<Request, ResolvedSignInput['keyRef'], Signed>;
  resolveSignInput: (req: Request) => Promise<ResolvedSignInput>;
}): Promise<Result> {
  const intent = await args.adapter.buildIntent(args.request);
  return await executeSigningIntent({
    intent,
    engines: args.engines,
    resolveSignInput: args.resolveSignInput,
  });
}
