import { test, expect } from '@playwright/test';

const IMPORT_PATHS = {
  engine: '/sdk/esm/core/signing/multichain/engines/webauthnP256.js',
} as const;

test.describe('WebAuthnP256Engine', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('builds Tempo WebAuthn signature from serialized credential', async ({ page }) => {
    const res = await page.evaluate(async ({ paths }) => {
      const { WebAuthnP256Engine } = await import(paths.engine);

      const bytesToB64 = (bytes: Uint8Array) => {
        let s = '';
        for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
        // eslint-disable-next-line no-undef
        return btoa(s);
      };
      const bytesToB64u = (bytes: Uint8Array) =>
        bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
      const strToB64u = (s: string) => bytesToB64u(new TextEncoder().encode(s));

      const challenge32 = new Uint8Array(32).fill(0x07);
      const expectedChallengeB64u = bytesToB64u(challenge32);

      const credentialId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const rawIdB64 = bytesToB64(credentialId);

      const clientData = JSON.stringify({
        type: 'webauthn.get',
        challenge: expectedChallengeB64u,
        origin: 'https://example.localhost',
      });

      const authenticatorData = new Uint8Array([9, 9, 9, 9]);
      const signatureDer = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]); // r=1, s=2

      const pubKeyX = new Uint8Array(32).fill(0x11);
      const pubKeyY = new Uint8Array(32).fill(0x22);

      const credential = {
        id: 'dummy',
        rawId: rawIdB64,
        type: 'public-key',
        authenticatorAttachment: undefined,
        response: {
          clientDataJSON: strToB64u(clientData),
          authenticatorData: bytesToB64u(authenticatorData),
          signature: bytesToB64u(signatureDer),
          userHandle: undefined,
        },
        clientExtensionResults: { prf: { results: { first: undefined, second: undefined } } },
      };

      const engine = new WebAuthnP256Engine();
      const out = await engine.sign(
        { kind: 'webauthn', algorithm: 'webauthnP256', challenge32, credential },
        { type: 'webauthnP256', credentialId, pubKeyX, pubKeyY },
      );

      const tail = out.slice(out.length - 128);
      const r = tail.slice(0, 32);
      const s = tail.slice(32, 64);
      const x = tail.slice(64, 96);
      const y = tail.slice(96, 128);

      return {
        typeId: out[0],
        rLast: r[31],
        sLast: s[31],
        xFirst: x[0],
        yFirst: y[0],
        xOk: Array.from(x).every((b) => b === 0x11),
        yOk: Array.from(y).every((b) => b === 0x22),
      };
    }, { paths: IMPORT_PATHS });

    expect(res.typeId).toBe(0x02);
    expect(res.rLast).toBe(1);
    expect(res.sLast).toBe(2);
    expect(res.xFirst).toBe(0x11);
    expect(res.yFirst).toBe(0x22);
    expect(res.xOk).toBeTruthy();
    expect(res.yOk).toBeTruthy();
  });
});
