export type Hex = `0x${string}`;

export type EvmAddress = Hex; // 20 bytes
export type EvmBytes = Hex; // 0x-prefixed hex bytes

export type EvmAccessListItem = {
  address: EvmAddress;
  storageKeys: Hex[]; // each 32 bytes
};

export type Eip1559UnsignedTx = {
  chainId: bigint;
  nonce: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gasLimit: bigint;
  to?: EvmAddress | null; // null/undefined = contract creation
  value: bigint;
  data?: EvmBytes; // defaults to 0x
  accessList?: EvmAccessListItem[]; // defaults to []
};
