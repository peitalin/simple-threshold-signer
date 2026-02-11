import { resolveWorkerBaseOrigin } from './workers';

export type MultichainWorkerKind = 'ethSigner' | 'tempoSigner';

function defaultWorkerPath(kind: MultichainWorkerKind): string {
  switch (kind) {
    case 'ethSigner':
      return '/sdk/workers/eth-signer.worker.js';
    case 'tempoSigner':
      return '/sdk/workers/tempo-signer.worker.js';
  }
}

function resolveOverride(kind: MultichainWorkerKind): string | undefined {
  const ovAny = (typeof window !== 'undefined' ? (window as any) : {}) as any;
  switch (kind) {
    case 'ethSigner':
      return typeof ovAny.__W3A_ETH_SIGNER_WORKER_URL__ === 'string' ? ovAny.__W3A_ETH_SIGNER_WORKER_URL__ : undefined;
    case 'tempoSigner':
      return typeof ovAny.__W3A_TEMPO_SIGNER_WORKER_URL__ === 'string' ? ovAny.__W3A_TEMPO_SIGNER_WORKER_URL__ : undefined;
  }
}

export function resolveMultichainWorkerUrl(
  kind: MultichainWorkerKind,
  opts?: { baseOrigin?: string }
): string {
  const baseOrigin =
    opts?.baseOrigin ||
    resolveWorkerBaseOrigin() ||
    (typeof window !== 'undefined' ? window.location.origin : '') ||
    'https://invalid.local';

  const candidate = resolveOverride(kind) || defaultWorkerPath(kind);
  if (/^https?:\/\//i.test(candidate)) return candidate;
  return new URL(candidate, baseOrigin).toString();
}

