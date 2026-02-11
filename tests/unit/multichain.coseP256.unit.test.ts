import { test, expect } from '@playwright/test';

const IMPORT_PATHS = {
  cose: '/sdk/esm/core/signing/webauthn/cose/coseP256.js',
} as const;

test.describe('COSE P-256 public key parsing', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('extracts x/y coordinates from a COSE EC2 key', async ({ page }) => {
    const res = await page.evaluate(async ({ paths }) => {
      const { coseP256PublicKeyToXY } = await import(paths.cose);

      const x = new Uint8Array(32).fill(0x11);
      const y = new Uint8Array(32).fill(0x22);

      // CBOR map(5): {1:2, 3:-7, -1:1, -2: bstr(32,x), -3:bstr(32,y)}
      const cose = new Uint8Array([
        0xa5,
        0x01, 0x02,
        0x03, 0x26,
        0x20, 0x01,
        0x21, 0x58, 0x20, ...x,
        0x22, 0x58, 0x20, ...y,
      ]);

      const out = coseP256PublicKeyToXY(cose);
      return {
        x: Array.from(out.x),
        y: Array.from(out.y),
      };
    }, { paths: IMPORT_PATHS });

    expect(res.x).toEqual(new Array(32).fill(0x11));
    expect(res.y).toEqual(new Array(32).fill(0x22));
  });
});
