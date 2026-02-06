import type { AuthService } from '../../core/AuthService';
import type { ScheduledHandler } from './types';
import type { RouterLogger } from '../logger';
import { coerceRouterLogger } from '../logger';

export interface CloudflareCronOptions {
  /**
   * When false, the handler is a no-op.
   * Defaults to true.
   */
  enabled?: boolean;
  /**
   * Legacy rotation flag used by older relay deployments.
   * Rotation logic is intentionally a no-op in the threshold-only stack.
   */
  rotate?: boolean;
  /**
   * Optional logger; defaults to silent.
   */
  logger?: RouterLogger | null;
  /**
   * When true, logs cron metadata for each tick.
   */
  verbose?: boolean;
}

export function createCloudflareCron(_service: AuthService, opts: CloudflareCronOptions = {}): ScheduledHandler {
  const enabled = opts.enabled !== false;
  const rotate = Boolean(opts.rotate);
  const verbose = Boolean(opts.verbose);
  const logger = coerceRouterLogger(opts.logger);

  return async (event) => {
    if (!enabled) return;

    if (verbose) {
      logger.info('[cron] tick', {
        scheduledTime: typeof event?.scheduledTime === 'number' ? event.scheduledTime : undefined,
        cron: typeof event?.cron === 'string' ? event.cron : undefined,
        rotate,
      });
    }

    // NOTE: The legacy key-rotation cron is intentionally not implemented here.
    // The lite/threshold-only refactor removes legacy unlock/rotation flows; keep this as a no-op
    // to preserve the Cloudflare router surface during the transition.
  };
}
