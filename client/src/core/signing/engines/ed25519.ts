import type { SigningEngine } from '../orchestration/types';
import { signDelegateAction } from '../chains/near/handlers/signDelegateAction';
import { signNep413Message } from '../chains/near/handlers/signNep413Message';
import { signTransactionsWithActions } from '../chains/near/handlers/signTransactionsWithActions';

export type NearEd25519SignRequest =
  | {
      kind: 'near-transactions-with-actions';
      algorithm: 'ed25519';
      payload: Parameters<typeof signTransactionsWithActions>[0];
    }
  | {
      kind: 'near-delegate-action';
      algorithm: 'ed25519';
      payload: Parameters<typeof signDelegateAction>[0];
    }
  | {
      kind: 'near-nep413-message';
      algorithm: 'ed25519';
      payload: Parameters<typeof signNep413Message>[0];
    };

export type NearEd25519SignOutput =
  | {
      kind: 'near-transactions-with-actions';
      result: Awaited<ReturnType<typeof signTransactionsWithActions>>;
    }
  | {
      kind: 'near-delegate-action';
      result: Awaited<ReturnType<typeof signDelegateAction>>;
    }
  | {
      kind: 'near-nep413-message';
      result: Awaited<ReturnType<typeof signNep413Message>>;
    };

export type NearEd25519KeyRef = {
  type: 'near-ed25519-runtime';
};

export const NEAR_ED25519_KEY_REF: NearEd25519KeyRef = {
  type: 'near-ed25519-runtime',
};

export class NearEd25519Engine
  implements SigningEngine<NearEd25519SignRequest, NearEd25519KeyRef, NearEd25519SignOutput> {
  readonly algorithm = 'ed25519' as const;

  async sign(req: NearEd25519SignRequest, keyRef: NearEd25519KeyRef): Promise<NearEd25519SignOutput> {
    if (keyRef.type !== 'near-ed25519-runtime') {
      throw new Error('[NearEd25519Engine] keyRef must be near-ed25519-runtime');
    }

    if (req.kind === 'near-transactions-with-actions') {
      return {
        kind: 'near-transactions-with-actions',
        result: await signTransactionsWithActions(req.payload),
      };
    }

    if (req.kind === 'near-delegate-action') {
      return {
        kind: 'near-delegate-action',
        result: await signDelegateAction(req.payload),
      };
    }

    if (req.kind === 'near-nep413-message') {
      return {
        kind: 'near-nep413-message',
        result: await signNep413Message(req.payload),
      };
    }

    const _exhaustive: never = req;
    return _exhaustive;
  }
}
