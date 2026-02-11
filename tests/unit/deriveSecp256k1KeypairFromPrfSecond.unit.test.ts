import { test, expect } from '@playwright/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { deriveSecp256k1KeypairFromPrfSecondB64u } from '@/core/signing/multichain/evm/deriveSecp256k1KeypairFromPrfSecond';
import { bytesToHex, hexToBytes } from '@/core/signing/multichain/evm/bytes';

test.describe('deriveSecp256k1KeypairFromPrfSecondB64u', () => {
  test('is deterministic and returns valid secp256k1 material', () => {
    const prfSecondB64u = Buffer.alloc(32, 7).toString('base64url');

    const first = deriveSecp256k1KeypairFromPrfSecondB64u({
      prfSecondB64u,
      nearAccountId: 'alice.testnet',
    });
    const second = deriveSecp256k1KeypairFromPrfSecondB64u({
      prfSecondB64u,
      nearAccountId: 'alice.testnet',
    });
    const otherAccount = deriveSecp256k1KeypairFromPrfSecondB64u({
      prfSecondB64u,
      nearAccountId: 'bob.testnet',
    });

    expect(first).toEqual(second);
    expect(first.privateKeyHex).not.toBe(otherAccount.privateKeyHex);

    expect(first.privateKeyHex).toMatch(/^0x[0-9a-f]{64}$/);
    expect(first.publicKeyHex).toMatch(/^0x[0-9a-f]{66}$/);
    expect(first.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);

    const expectedPub = bytesToHex(secp256k1.getPublicKey(hexToBytes(first.privateKeyHex), true));
    expect(first.publicKeyHex).toBe(expectedPub);
  });
});
