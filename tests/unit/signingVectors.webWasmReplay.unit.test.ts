import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const IMPORT_PATHS = {
  ethSignerWasm: '/sdk/esm/core/signing/chainAdaptors/evm/ethSignerWasm.js',
  tempoSignerWasm: '/sdk/esm/core/signing/chainAdaptors/tempo/tempoSignerWasm.js',
  signerGateway: '/sdk/esm/core/signing/workers/signerWorkerManager/gateway.js',
} as const;

const VECTORS_PATH = path.resolve(
  process.cwd(),
  '../crates/signer-core/fixtures/signing-vectors/v1.json',
);
const CANONICAL_VECTORS = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));

test.describe('canonical vector replay via worker-facing wasm bindings', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('replays secp256k1 and tx-finalization vectors through worker wrappers', async ({
    page,
  }) => {
    const replay = await page.evaluate(
      async ({ paths, vectors }) => {
        const {
          deriveThresholdSecp256k1ClientShareWasm,
          deriveSecp256k1KeypairFromPrfSecondWasm,
          mapAdditiveShareToThresholdSignaturesShare2pWasm,
          validateSecp256k1PublicKey33Wasm,
          addSecp256k1PublicKeys33Wasm,
          computeEip1559TxHashWasm,
          encodeEip1559SignedTxFromSignature65Wasm,
        } = await import(paths.ethSignerWasm);
        const { computeTempoSenderHashWasm, encodeTempoSignedTxWasm } = await import(
          paths.tempoSignerWasm
        );
        const { requestMultichainWorkerOperation } = await import(paths.signerGateway);

        const workerCtx = {
          requestWorkerOperation: async ({ kind, request }: { kind: string; request: unknown }) =>
            await requestMultichainWorkerOperation({
              kind: kind as any,
              request: request as any,
            }),
        };

        const fromHex = (hex: string): Uint8Array => {
          const clean = String(hex).trim().replace(/^0x/i, '');
          if (clean.length % 2 !== 0) throw new Error(`invalid hex length: ${clean.length}`);
          const out = new Uint8Array(clean.length / 2);
          for (let i = 0; i < clean.length; i += 2) {
            out[i / 2] = Number.parseInt(clean.slice(i, i + 2), 16);
          }
          return out;
        };

        const toHex = (bytes: Uint8Array): string =>
          Array.from(bytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');

        const toBase64Url = (bytes: Uint8Array): string => {
          let binary = '';
          for (const b of bytes) binary += String.fromCharCode(b);
          return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        };

        const toTempoTx = (tx: any) => ({
          chainId: BigInt(tx.chain_id),
          maxPriorityFeePerGas: BigInt(tx.max_priority_fee_per_gas),
          maxFeePerGas: BigInt(tx.max_fee_per_gas),
          gasLimit: BigInt(tx.gas_limit),
          calls: (tx.calls || []).map((c: any) => ({
            to: c.to,
            value: BigInt(c.value),
            input: c.input ?? '0x',
          })),
          accessList: (tx.access_list || []).map((item: any) => ({
            address: item.address,
            storageKeys: item.storage_keys ?? item.storageKeys ?? [],
          })),
          nonceKey: BigInt(tx.nonce_key),
          nonce: BigInt(tx.nonce),
          validBefore: tx.valid_before == null ? null : BigInt(tx.valid_before),
          validAfter: tx.valid_after == null ? null : BigInt(tx.valid_after),
          feeToken: tx.fee_token ?? null,
          feePayerSignature: tx.fee_payer_signature ?? { kind: 'none' as const },
          aaAuthorizationList: [],
        });

        const toEip1559Tx = (tx: any) => ({
          chainId: BigInt(tx.chain_id),
          nonce: BigInt(tx.nonce),
          maxPriorityFeePerGas: BigInt(tx.max_priority_fee_per_gas),
          maxFeePerGas: BigInt(tx.max_fee_per_gas),
          gasLimit: BigInt(tx.gas_limit),
          to: tx.to ?? null,
          value: BigInt(tx.value),
          data: tx.data ?? '0x',
          accessList: (tx.access_list || []).map((item: any) => ({
            address: item.address,
            storageKeys: item.storage_keys ?? item.storageKeys ?? [],
          })),
        });

        const secp = vectors.secp256k1;
        const txFinalization = vectors.tx_finalization;

        const prfFirstB64u = toBase64Url(fromHex(secp.derive_threshold_client_share.prf_first32_hex));
        const deriveShare = await deriveThresholdSecp256k1ClientShareWasm({
          prfFirstB64u,
          userId: secp.derive_threshold_client_share.user_id,
          derivationPath: Number(secp.derive_threshold_client_share.derivation_path),
          workerCtx: workerCtx as any,
        });
        const deriveShareCombined = new Uint8Array(
          deriveShare.clientSigningShare32.length + deriveShare.clientVerifyingShareBytes.length,
        );
        deriveShareCombined.set(deriveShare.clientSigningShare32, 0);
        deriveShareCombined.set(
          deriveShare.clientVerifyingShareBytes,
          deriveShare.clientSigningShare32.length,
        );

        const deriveKeypair = await deriveSecp256k1KeypairFromPrfSecondWasm({
          prfSecondB64u: toBase64Url(fromHex(secp.derive_keypair_from_prf_second.prf_second_hex)),
          nearAccountId: secp.derive_keypair_from_prf_second.near_account_id,
          workerCtx: workerCtx as any,
        });
        const deriveKeypairHex = `${deriveKeypair.privateKeyHex.replace(/^0x/i, '')}${deriveKeypair.publicKeyHex.replace(/^0x/i, '')}${deriveKeypair.ethereumAddress.replace(/^0x/i, '')}`;

        const mappedShare = await mapAdditiveShareToThresholdSignaturesShare2pWasm({
          additiveShare32: fromHex(secp.map_additive_share_2p.additive_share32_hex),
          participantId: Number(secp.map_additive_share_2p.participant_id),
          workerCtx: workerCtx as any,
        });

        const validatedPk = await validateSecp256k1PublicKey33Wasm({
          publicKey33: fromHex(secp.validate_public_key_33.public_key33_hex),
          workerCtx: workerCtx as any,
        });

        const addedPk = await addSecp256k1PublicKeys33Wasm({
          left33: fromHex(secp.add_public_keys_33.left33_hex),
          right33: fromHex(secp.add_public_keys_33.right33_hex),
          workerCtx: workerCtx as any,
        });

        const eip = txFinalization.eip1559;
        const eipTx = toEip1559Tx(eip.tx);
        const eipHash = await computeEip1559TxHashWasm(eipTx, workerCtx as any);
        const signature65 = new Uint8Array(65);
        signature65.set(fromHex(eip.signature.r_hex), 0);
        signature65.set(fromHex(eip.signature.s_hex), 32);
        signature65[64] = Number(eip.signature.y_parity) & 1;
        const eipRaw = await encodeEip1559SignedTxFromSignature65Wasm({
          tx: eipTx,
          signature65,
          workerCtx: workerCtx as any,
        });

        const tempo = txFinalization.tempo;
        const tempoPlaceholderTx = toTempoTx(tempo.placeholder.tx);
        const tempoPlaceholderAltTx = toTempoTx({
          ...tempo.placeholder.tx,
          fee_token: tempo.placeholder.alt_fee_token,
        });
        const tempoPlaceholderHash = await computeTempoSenderHashWasm(
          tempoPlaceholderTx,
          workerCtx as any,
        );
        const tempoPlaceholderHashAlt = await computeTempoSenderHashWasm(
          tempoPlaceholderAltTx,
          workerCtx as any,
        );
        const tempoPlaceholderRaw = await encodeTempoSignedTxWasm({
          tx: tempoPlaceholderTx,
          senderSignature: fromHex(tempo.placeholder.sender_signature_hex),
          workerCtx: workerCtx as any,
        });

        const tempoNoneHashA = await computeTempoSenderHashWasm(
          toTempoTx(tempo.none.tx_a),
          workerCtx as any,
        );
        const tempoNoneHashB = await computeTempoSenderHashWasm(
          toTempoTx(tempo.none.tx_b),
          workerCtx as any,
        );

        return {
          deriveShareHex: toHex(deriveShareCombined),
          deriveKeypairHex,
          mappedShareHex: toHex(mappedShare),
          validatedPkHex: toHex(validatedPk),
          addedPkHex: toHex(addedPk),
          eipHashHex: toHex(eipHash),
          eipRawHex: toHex(eipRaw),
          tempoPlaceholderHashHex: toHex(tempoPlaceholderHash),
          tempoPlaceholderHashAltHex: toHex(tempoPlaceholderHashAlt),
          tempoPlaceholderRawHex: toHex(tempoPlaceholderRaw),
          tempoNoneHashAHex: toHex(tempoNoneHashA),
          tempoNoneHashBHex: toHex(tempoNoneHashB),
        };
      },
      { paths: IMPORT_PATHS, vectors: CANONICAL_VECTORS },
    );

    expect(replay.deriveShareHex).toBe(
      CANONICAL_VECTORS.secp256k1.derive_threshold_client_share.expected_hex,
    );
    expect(replay.deriveKeypairHex).toBe(
      CANONICAL_VECTORS.secp256k1.derive_keypair_from_prf_second.expected_hex,
    );
    expect(replay.mappedShareHex).toBe(CANONICAL_VECTORS.secp256k1.map_additive_share_2p.expected_hex);
    expect(replay.validatedPkHex).toBe(CANONICAL_VECTORS.secp256k1.validate_public_key_33.expected_hex);
    expect(replay.addedPkHex).toBe(CANONICAL_VECTORS.secp256k1.add_public_keys_33.expected_hex);

    expect(replay.eipHashHex).toBe(CANONICAL_VECTORS.tx_finalization.eip1559.expected_hash_hex);
    expect(replay.eipRawHex).toBe(CANONICAL_VECTORS.tx_finalization.eip1559.expected_raw_hex);

    expect(replay.tempoPlaceholderHashHex).toBe(
      CANONICAL_VECTORS.tx_finalization.tempo.placeholder.expected_sender_hash_hex,
    );
    expect(replay.tempoPlaceholderHashAltHex).toBe(
      CANONICAL_VECTORS.tx_finalization.tempo.placeholder.expected_sender_hash_alt_hex,
    );
    expect(replay.tempoPlaceholderRawHex).toBe(
      CANONICAL_VECTORS.tx_finalization.tempo.placeholder.expected_raw_hex,
    );

    expect(replay.tempoNoneHashAHex).toBe(
      CANONICAL_VECTORS.tx_finalization.tempo.none.expected_sender_hash_a_hex,
    );
    expect(replay.tempoNoneHashBHex).toBe(
      CANONICAL_VECTORS.tx_finalization.tempo.none.expected_sender_hash_b_hex,
    );
  });
});
