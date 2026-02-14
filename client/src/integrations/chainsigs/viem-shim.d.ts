declare module 'viem' {
  // Minimal ambient declaration so TypeScript accepts dynamic imports when
  // building the SDK. Applications should use viem's own type declarations.
  export const keccak256: (...args: any[]) => any;
  export const parseTransaction: (...args: any[]) => any;
  export const recoverTransactionAddress: (...args: any[]) => Promise<any>;
  export const serializeTransaction: (...args: any[]) => any;
  const mod: any;
  export default mod;
}
