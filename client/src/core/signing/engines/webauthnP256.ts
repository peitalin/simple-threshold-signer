import { concatBytes } from '../chains/evm/bytes';
import type { KeyRef, SignRequest, SignatureBytes, SigningEngine } from '../orchestration/types';

const WEBAUTHN_TYPE_ID = 0x02;

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function pad32(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 32) throw new Error('[WebAuthnP256Engine] DER integer too long');
  if (bytes.length === 32) return bytes;
  const out = new Uint8Array(32);
  out.set(bytes, 32 - bytes.length);
  return out;
}

function stripDerIntLeadingZeros(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0x00) i++;
  return bytes.slice(i);
}

function readDerLength(der: Uint8Array, offset: number): { len: number; next: number } {
  const first = der[offset];
  if (first === undefined) throw new Error('[WebAuthnP256Engine] DER truncated');
  if ((first & 0x80) === 0) return { len: first, next: offset + 1 };

  const n = first & 0x7f;
  if (n === 0 || n > 4) throw new Error('[WebAuthnP256Engine] DER invalid length');
  if (offset + 1 + n > der.length) throw new Error('[WebAuthnP256Engine] DER truncated length');
  let len = 0;
  for (let i = 0; i < n; i++) len = (len << 8) | der[offset + 1 + i];
  return { len, next: offset + 1 + n };
}

function parseDerEcdsaSignatureP256(der: Uint8Array): { r32: Uint8Array; s32: Uint8Array } {
  // ASN.1 DER: SEQUENCE { INTEGER r; INTEGER s }
  let o = 0;
  if (der[o++] !== 0x30) throw new Error('[WebAuthnP256Engine] DER signature must be a SEQUENCE');
  const seqLen = readDerLength(der, o);
  o = seqLen.next;
  const seqEnd = o + seqLen.len;
  if (seqEnd !== der.length) throw new Error('[WebAuthnP256Engine] DER signature length mismatch');

  if (der[o++] !== 0x02) throw new Error('[WebAuthnP256Engine] DER signature missing INTEGER(r)');
  const rLen = readDerLength(der, o);
  o = rLen.next;
  const rBytes = der.slice(o, o + rLen.len);
  o += rLen.len;

  if (der[o++] !== 0x02) throw new Error('[WebAuthnP256Engine] DER signature missing INTEGER(s)');
  const sLen = readDerLength(der, o);
  o = sLen.next;
  const sBytes = der.slice(o, o + sLen.len);
  o += sLen.len;

  if (o !== seqEnd) throw new Error('[WebAuthnP256Engine] DER signature trailing bytes');

  const r = stripDerIntLeadingZeros(rBytes);
  const s = stripDerIntLeadingZeros(sBytes);
  return { r32: pad32(r), s32: pad32(s) };
}

function bytesToBase64Url(bytes: Uint8Array): string {
  // WebAuthn clientDataJSON.challenge is base64url (no padding).
  const base64 = (() => {
    if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    // eslint-disable-next-line no-undef
    return btoa(s);
  })();
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64ToBytes(base64: string): Uint8Array {
  const normalized = String(base64 || '').trim();
  if (!normalized) return new Uint8Array();
  if (typeof Buffer !== 'undefined') return Uint8Array.from(Buffer.from(normalized, 'base64'));
  // eslint-disable-next-line no-undef
  const bin = atob(normalized);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base64UrlToBytes(base64Url: string): Uint8Array {
  const normalized = String(base64Url || '').trim().replace(/-/g, '+').replace(/_/g, '/');
  if (!normalized) return new Uint8Array();
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return base64ToBytes(padded);
}

export class WebAuthnP256Engine implements SigningEngine {
  readonly algorithm = 'webauthnP256' as const;

  async sign(req: SignRequest, keyRef: KeyRef): Promise<SignatureBytes> {
    if (req.kind !== 'webauthn' || req.algorithm !== 'webauthnP256') {
      throw new Error('[WebAuthnP256Engine] unsupported sign request');
    }
    if (req.challenge32.length !== 32) {
      throw new Error('[WebAuthnP256Engine] challenge32 must be 32 bytes');
    }
    if (keyRef.type !== 'webauthnP256') {
      throw new Error('[WebAuthnP256Engine] keyRef must be webauthnP256');
    }

    if (keyRef.pubKeyX.length !== 32 || keyRef.pubKeyY.length !== 32) {
      throw new Error('[WebAuthnP256Engine] pubKeyX/pubKeyY must be 32 bytes each');
    }
    if (keyRef.credentialId.length === 0) {
      throw new Error('[WebAuthnP256Engine] credentialId must be non-empty');
    }

    const fromSerializedCredential = (credential: any): SignatureBytes => {
      const rawIdB64 = String(credential?.rawId || '').trim();
      const rawId = base64ToBytes(rawIdB64);
      if (!bytesEq(rawId, keyRef.credentialId)) {
        throw new Error('[WebAuthnP256Engine] WebAuthn credential rawId does not match keyRef');
      }

      const response = credential?.response;
      const authenticatorData = base64UrlToBytes(String(response?.authenticatorData || ''));
      const clientDataJSON = base64UrlToBytes(String(response?.clientDataJSON || ''));
      const signatureDer = base64UrlToBytes(String(response?.signature || ''));
      if (authenticatorData.length === 0 || clientDataJSON.length === 0 || signatureDer.length === 0) {
        throw new Error('[WebAuthnP256Engine] missing authenticatorData/clientDataJSON/signature in credential');
      }

      // Sanity check challenge binding.
      try {
        const json = JSON.parse(new TextDecoder().decode(clientDataJSON)) as { type?: unknown; challenge?: unknown };
        if (json?.type !== 'webauthn.get') {
          throw new Error('[WebAuthnP256Engine] unexpected clientData.type');
        }
        const expectedChallenge = bytesToBase64Url(req.challenge32);
        if (json?.challenge !== expectedChallenge) {
          throw new Error('[WebAuthnP256Engine] clientData.challenge mismatch');
        }
      } catch (e: any) {
        throw new Error(String(e?.message || e || '[WebAuthnP256Engine] invalid clientDataJSON'));
      }

      const { r32, s32 } = parseDerEcdsaSignatureP256(signatureDer);
      const webauthnData = concatBytes([authenticatorData, clientDataJSON]);
      return concatBytes([Uint8Array.from([WEBAUTHN_TYPE_ID]), webauthnData, r32, s32, keyRef.pubKeyX, keyRef.pubKeyY]);
    };

    if (req.credential) {
      return fromSerializedCredential(req.credential);
    }

    if (typeof navigator === 'undefined' || !navigator.credentials || typeof navigator.credentials.get !== 'function') {
      throw new Error('[WebAuthnP256Engine] WebAuthn not available (must run in a browser context)');
    }

    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: req.challenge32,
        allowCredentials: [{ type: 'public-key', id: keyRef.credentialId }],
        rpId: req.rpId ?? keyRef.rpId,
        userVerification: 'preferred',
      },
    })) as PublicKeyCredential | null;

    if (!assertion) throw new Error('[WebAuthnP256Engine] user cancelled WebAuthn assertion');

    const rawId = new Uint8Array(assertion.rawId);
    if (!bytesEq(rawId, keyRef.credentialId)) {
      throw new Error('[WebAuthnP256Engine] WebAuthn assertion returned unexpected credentialId');
    }

    const resp = assertion.response as AuthenticatorAssertionResponse;
    if (!resp || !resp.authenticatorData || !resp.clientDataJSON || !resp.signature) {
      throw new Error('[WebAuthnP256Engine] invalid WebAuthn assertion response');
    }

    const authenticatorData = new Uint8Array(resp.authenticatorData);
    const clientDataJSON = new Uint8Array(resp.clientDataJSON);
    const signatureDer = new Uint8Array(resp.signature);

    // Sanity check challenge binding.
    try {
      const json = JSON.parse(new TextDecoder().decode(clientDataJSON)) as { type?: unknown; challenge?: unknown };
      if (json?.type !== 'webauthn.get') {
        throw new Error('[WebAuthnP256Engine] unexpected clientData.type');
      }
      const expectedChallenge = bytesToBase64Url(req.challenge32);
      if (json?.challenge !== expectedChallenge) {
        throw new Error('[WebAuthnP256Engine] clientData.challenge mismatch');
      }
    } catch (e: any) {
      throw new Error(String(e?.message || e || '[WebAuthnP256Engine] invalid clientDataJSON'));
    }

    const { r32, s32 } = parseDerEcdsaSignatureP256(signatureDer);
    const webauthnData = concatBytes([authenticatorData, clientDataJSON]);

    // Tempo WebAuthn signature encoding:
    // 0x02 || webauthn_data(authenticatorData||clientDataJSON) || r || s || pub_key_x || pub_key_y
    return concatBytes([Uint8Array.from([WEBAUTHN_TYPE_ID]), webauthnData, r32, s32, keyRef.pubKeyX, keyRef.pubKeyY]);
  }
}
