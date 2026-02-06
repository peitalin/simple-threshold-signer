import type { Eip1559UnsignedTx, EvmAccessListItem, EvmAddress, EvmBytes, Hex } from '../evm/types';
import type { RlpValue } from '../evm/rlp';

export type TempoCall = {
  to: EvmAddress;          // 20 bytes
  value: bigint;          // wei
  input?: EvmBytes;       // calldata, defaults to 0x
};

export type TempoFeePayerSignature =
  | { kind: 'none' }
  | { kind: 'placeholder' }
  | { kind: 'signed'; v: 0 | 1; r: Hex; s: Hex };

export type TempoUnsignedTx = {
  chainId: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gasLimit: bigint;
  calls: TempoCall[]; // must be non-empty
  accessList?: EvmAccessListItem[];
  nonceKey: bigint;
  nonce: bigint;
  validBefore?: bigint | null;
  validAfter?: bigint | null;
  feeToken?: EvmAddress | null;
  feePayerSignature?: TempoFeePayerSignature;
  aaAuthorizationList?: RlpValue; // default []
  keyAuthorization?: RlpValue; // optional; omitted when undefined
};

export type TempoSigningRequest =
  | {
      chain: 'tempo';
      kind: 'tempoTransaction';
      tx: TempoUnsignedTx;
      senderSignatureAlgorithm: 'secp256k1' | 'webauthn-p256';
    }
  | {
      chain: 'tempo';
      kind: 'eip1559';
      tx: Eip1559UnsignedTx;
      senderSignatureAlgorithm: 'secp256k1';
    };

