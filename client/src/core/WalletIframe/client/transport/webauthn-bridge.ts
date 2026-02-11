import { isObject } from '../../../../../../shared/src/utils/validation';
import { serializeRegistrationCredentialWithPRF, serializeAuthenticationCredentialWithPRF } from '../../../signing/webauthn/credentials/helpers';
import { WebAuthnBridgeMessage } from '../../../signing/webauthn/fallbacks';

type CreateReq = { requestId?: string; publicKey?: PublicKeyCredentialCreationOptions };
type GetReq = { requestId?: string; publicKey?: PublicKeyCredentialRequestOptions };

type BridgeResultType = 'WALLET_WEBAUTHN_CREATE_RESULT' | 'WALLET_WEBAUTHN_GET_RESULT';

export function postBridgeResult(
  source: WindowProxy | null,
  type: BridgeResultType,
  requestId: string,
  ok: boolean,
  payload: { credential?: unknown; error?: string },
): void {
  // Reply directly to the requesting window; wildcard target avoids transient
  // 'null' origin warnings during early navigation while remaining safe since
  // we already validated the sender's origin before bridging.
  source?.postMessage({ type, requestId, ok, ...payload }, '*');
}

export function handleWebAuthnBridgeMessage(
  kind: typeof WebAuthnBridgeMessage.Create | typeof WebAuthnBridgeMessage.Get,
  raw: unknown,
  e: MessageEvent
): void {
  if (kind === WebAuthnBridgeMessage.Create) {
    void handleWebAuthnCreate(raw as CreateReq, e);
    return;
  }
  void handleWebAuthnGet(raw as GetReq, e);
}

function formatBridgeError(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function handleWebAuthnCreate(req: CreateReq, e: MessageEvent): Promise<void> {
  const requestId = req?.requestId || '';
  if (!isObject(req?.publicKey)) {
    postBridgeResult(e.source as WindowProxy | null, WebAuthnBridgeMessage.CreateResult, requestId, false, { error: 'publicKey options required' });
    return;
  }
  if (!navigator.credentials?.create) {
    postBridgeResult(e.source as WindowProxy | null, WebAuthnBridgeMessage.CreateResult, requestId, false, { error: 'WebAuthn create not available' });
    return;
  }
  try {
    const src = req.publicKey as PublicKeyCredentialCreationOptions;
    const rpName = src.rp?.name || 'WebAuthn';
    const rpId = src.rp?.id || window.location.hostname;
    const pub: PublicKeyCredentialCreationOptions = { ...src, rp: { name: rpName, id: rpId } };
    const cred = await navigator.credentials.create({ publicKey: pub }) as PublicKeyCredential;
    const serialized = serializeRegistrationCredentialWithPRF({ credential: cred, firstPrfOutput: true, secondPrfOutput: true });
    postBridgeResult(e.source as WindowProxy | null, WebAuthnBridgeMessage.CreateResult, requestId, true, { credential: serialized });
  } catch (err) {
    const message = formatBridgeError(err);
    console.warn('[IframeTransport][bridge] CREATE failed', { requestId, err: message });
    postBridgeResult(e.source as WindowProxy | null, WebAuthnBridgeMessage.CreateResult, requestId, false, { error: message });
  }
}

async function handleWebAuthnGet(req: GetReq, e: MessageEvent): Promise<void> {
  const requestId = req?.requestId || '';
  if (!isObject(req?.publicKey)) {
    postBridgeResult(e.source as WindowProxy | null, WebAuthnBridgeMessage.GetResult, requestId, false, { error: 'publicKey options required' });
    return;
  }
  if (!navigator.credentials?.get) {
    postBridgeResult(e.source as WindowProxy | null, WebAuthnBridgeMessage.GetResult, requestId, false, { error: 'WebAuthn get not available' });
    return;
  }
  try {
    const src = req.publicKey as PublicKeyCredentialRequestOptions;
    const rpId = src.rpId || window.location.hostname;
    const pub: PublicKeyCredentialRequestOptions = { ...src, rpId };
    const cred = await navigator.credentials.get({ publicKey: pub }) as PublicKeyCredential;
    const serialized = serializeAuthenticationCredentialWithPRF({ credential: cred, firstPrfOutput: true, secondPrfOutput: true });
    postBridgeResult(e.source as WindowProxy | null, WebAuthnBridgeMessage.GetResult, requestId, true, { credential: serialized });
  } catch (err) {
    const message = formatBridgeError(err);
    console.warn('[IframeTransport][bridge] GET failed', { requestId, err: message });
    postBridgeResult(e.source as WindowProxy | null, WebAuthnBridgeMessage.GetResult, requestId, false, { error: message });
  }
}
