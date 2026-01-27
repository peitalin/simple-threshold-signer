import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import type { CreateAccountAndRegisterRequest, CreateAccountAndRegisterResult } from '../../../core/types';

export function registerCreateAccountAndRegisterUser(router: ExpressRouter, ctx: ExpressRelayContext): void {
  router.post('/create_account_and_register_user', async (req: Request, res: Response) => {
    try {
      const body = (req.body || {}) as any as CreateAccountAndRegisterRequest & Record<string, unknown>;
      const new_account_id = String(body.new_account_id || '').trim();
      const new_public_key = typeof body.new_public_key === 'string' ? body.new_public_key.trim() : '';
      const device_number = (body as any).device_number;
      const threshold_ed25519 = (body as any).threshold_ed25519;
      const rp_id = typeof body.rp_id === 'string' ? body.rp_id.trim() : '';
      const webauthn_registration = (body as any).webauthn_registration;
      const authenticator_options = (body as any).authenticator_options;

      if (!new_account_id) return res.status(400).json({ success: false, error: 'Missing or invalid new_account_id' });
      if (!rp_id) return res.status(400).json({ success: false, error: 'Missing or invalid rp_id' });
      if (!webauthn_registration || typeof webauthn_registration !== 'object') {
        return res.status(400).json({ success: false, error: 'Missing or invalid webauthn_registration' });
      }

      const result = await ctx.service.createAccountAndRegisterUser({
        new_account_id,
        ...(new_public_key ? { new_public_key } : {}),
        device_number,
        ...(threshold_ed25519 ? { threshold_ed25519 } : {}),
        rp_id,
        webauthn_registration,
        expected_origin: (req.headers?.origin || req.headers?.Origin) as string | undefined,
        authenticator_options
      });

      const response: CreateAccountAndRegisterResult = result;
      if (response.success) res.status(200).json(response);
      else res.status(400).json(response);
    } catch (error: unknown) {
      const message = (error && typeof error === 'object' && 'message' in error)
        ? String((error as { message?: unknown }).message || 'internal error')
        : 'internal error';
      res.status(500).json({ success: false, error: message });
    }
  });
}
