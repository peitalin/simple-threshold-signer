import type { Request, Response, Router as ExpressRouter } from 'express';
import { buildCorsOrigins } from '../../core/SessionService';
import type { RelayRouterOptions } from '../relay';

function withCors(res: Response, opts?: RelayRouterOptions, req?: Request): void {
  const pathname = String((req as any)?.path || '').trim();

  // Public CORS: allow any origin to read `/healthz` and `/readyz`.
  // These endpoints only expose non-sensitive deployment metadata and are used by SDKs
  // for auto-discovery (e.g., correct relayerAccountId postfix).
  if (pathname === '/healthz' || pathname === '/readyz') {
    res.set('Access-Control-Allow-Origin', '*');
    (res as any).removeHeader?.('Access-Control-Allow-Credentials');
    res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    return;
  }

  if (!opts?.corsOrigins) return;

  let allowedOrigin: string | '*' | undefined;
  const normalized = buildCorsOrigins(...(opts.corsOrigins || []));
  if (normalized === '*') {
    allowedOrigin = '*';
    res.set('Access-Control-Allow-Origin', '*');
  } else if (Array.isArray(normalized)) {
    const origin = String((req as any)?.headers?.origin || '').trim();
    if (origin && normalized.includes(origin)) {
      allowedOrigin = origin;
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
    }
  }

  res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  // Only advertise credentials when we echo back a specific origin (not '*')
  if (allowedOrigin && allowedOrigin !== '*') {
    res.set('Access-Control-Allow-Credentials', 'true');
  }
}

export function installCors(router: ExpressRouter, opts: RelayRouterOptions): void {
  // Optional CORS: implemented here to keep setup simple for example relayers.
  // If you prefer custom CORS middleware, omit `corsOrigins` and wire your own.
  router.use((req: Request, res: Response, next: any) => {
    withCors(res, opts, req);
    const method = String((req as any)?.method || '').toUpperCase();
    const pathname = String((req as any)?.path || '').trim();
    const isPublicPreflight = pathname === '/healthz' || pathname === '/readyz';
    if ((opts.corsOrigins || isPublicPreflight) && method === 'OPTIONS') {
      res.status(204).send('');
      return;
    }
    next();
  });
}
