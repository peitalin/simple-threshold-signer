import type {
  KeyRef,
  SignRequest,
  SigningEngine,
  SigningIntent,
} from './types';

export async function executeSigningIntent<Result>(args: {
  intent: SigningIntent<unknown, Result>;
  engines: Record<string, SigningEngine>;
  resolveSignInput: (req: SignRequest) => Promise<{ signReq: SignRequest; keyRef: KeyRef }>;
}): Promise<Result> {
  const signatures: Uint8Array[] = [];
  for (const pendingReq of args.intent.signRequests) {
    const { signReq, keyRef } = await args.resolveSignInput(pendingReq);
    const engine = args.engines[signReq.algorithm];
    if (!engine) throw new Error(`[chains] missing engine for algorithm: ${signReq.algorithm}`);
    signatures.push(await engine.sign(signReq, keyRef));
  }
  return await args.intent.finalize(signatures);
}
