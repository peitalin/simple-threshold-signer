import type {
  SigningEngine,
  SigningIntent,
} from './types';

export async function executeSigningIntent<
  Result,
  Request extends { algorithm: string },
  Key,
  Signed,
>(args: {
  intent: SigningIntent<unknown, Result, Request, Signed>;
  engines: Record<string, SigningEngine<Request, Key, Signed>>;
  resolveSignInput: (req: Request) => Promise<{ signReq: Request; keyRef: Key }>;
}): Promise<Result> {
  const signatures: Signed[] = [];
  for (const pendingReq of args.intent.signRequests) {
    const { signReq, keyRef } = await args.resolveSignInput(pendingReq);
    const engine = args.engines[signReq.algorithm];
    if (!engine) throw new Error(`[chains] missing engine for algorithm: ${signReq.algorithm}`);
    signatures.push(await engine.sign(signReq, keyRef));
  }
  return await args.intent.finalize(signatures);
}
