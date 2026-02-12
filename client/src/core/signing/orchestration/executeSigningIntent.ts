import type { SigningEngineMap, SigningIntent } from './types';

export async function executeSigningIntent<
  Result,
  Request extends { algorithm: string },
  Signed,
  ResolvedSignInput extends { signReq: Request; keyRef: unknown },
>(args: {
  intent: SigningIntent<unknown, Result, Request, Signed>;
  engines: SigningEngineMap<Request, ResolvedSignInput['keyRef'], Signed>;
  resolveSignInput: (req: Request) => Promise<ResolvedSignInput>;
}): Promise<Result> {
  const signatures: Signed[] = [];
  for (const pendingReq of args.intent.signRequests) {
    const { signReq, keyRef } = await args.resolveSignInput(pendingReq);
    const algorithm = signReq.algorithm as Request['algorithm'] & string;
    const engine = args.engines[algorithm];
    if (!engine) throw new Error(`[chains] missing engine for algorithm: ${signReq.algorithm}`);
    signatures.push(await engine.sign(signReq, keyRef));
  }
  return await args.intent.finalize(signatures);
}
