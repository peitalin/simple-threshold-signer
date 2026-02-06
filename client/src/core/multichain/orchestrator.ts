import type { ChainAdapter, KeyRef, SignerEngine, SigningIntent, SignatureBytes } from './types';

export type ConfirmFn<UiModel> = (args: { chain: string; uiModel: UiModel }) => Promise<{ approved: boolean }>;

export async function signWithAdapters<Request, UiModel, Result>(args: {
  request: Request;
  adapter: ChainAdapter<Request, UiModel, Result>;
  engines: Record<string, SignerEngine>;
  keyRefsByAlgorithm: Record<string, KeyRef>;
  confirm: ConfirmFn<UiModel>;
}): Promise<Result> {
  const intent = (await args.adapter.buildIntent(args.request)) as SigningIntent<UiModel, Result>;

  const decision = await args.confirm({ chain: intent.chain, uiModel: intent.uiModel });
  if (!decision.approved) {
    throw new Error(`[multichain] user rejected ${intent.chain} intent`);
  }

  const signatures: SignatureBytes[] = [];
  for (const signReq of intent.signRequests) {
    const engine = args.engines[signReq.algorithm];
    if (!engine) {
      throw new Error(`[multichain] missing engine for algorithm: ${signReq.algorithm}`);
    }
    const keyRef = args.keyRefsByAlgorithm[signReq.algorithm];
    if (!keyRef) {
      throw new Error(`[multichain] missing keyRef for algorithm: ${signReq.algorithm}`);
    }
    signatures.push(await engine.sign(signReq, keyRef));
  }

  return await intent.finalize(signatures);
}

