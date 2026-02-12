import { executeSigningIntent } from './executeSigningIntent';
import type {
  ChainAdapter,
  SigningEngine,
} from './types';

export async function signWithIntent<
  Input,
  Result,
  Request extends { algorithm: string },
  Key,
  Signed,
>(args: {
  adapter: ChainAdapter<Input, unknown, Result, Request, Signed>;
  request: Input;
  engines: Record<string, SigningEngine<Request, Key, Signed>>;
  resolveSignInput: (req: Request) => Promise<{ signReq: Request; keyRef: Key }>;
}): Promise<Result> {
  const intent = await args.adapter.buildIntent(args.request);
  return await executeSigningIntent({
    intent,
    engines: args.engines,
    resolveSignInput: args.resolveSignInput,
  });
}
