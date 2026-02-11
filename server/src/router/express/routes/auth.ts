import type { Router as ExpressRouter } from 'express';
import { parseSessionKind } from '../../relay';
import type { ExpressRelayContext } from '../createRelayRouter';

type ProviderId = 'passkey' | 'google';
type ActionId = 'options' | 'verify';

function getOrigin(headers: any): string | undefined {
  const raw = headers?.origin ?? headers?.Origin;
  if (typeof raw === 'string') return raw.trim() || undefined;
  return undefined;
}

export function registerAuthRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  async function requireAppSession(req: any, res: any): Promise<{ userId: string; claims: any } | null> {
    const session = ctx.opts.session;
    if (!session) {
      res.status(501).json({ ok: false, code: 'sessions_disabled', message: 'Sessions are not configured' });
      return null;
    }
    const parsed = await session.parse(req.headers || {});
    if (!parsed.ok) {
      res.status(401).json({ ok: false, code: 'unauthorized', message: 'No valid session' });
      return null;
    }
    const claims: any = (parsed as any).claims || {};
    const kind = typeof claims.kind === 'string' ? claims.kind.trim() : '';
    if (kind !== 'app_session_v1') {
      res.status(401).json({ ok: false, code: 'unauthorized', message: 'No valid app session' });
      return null;
    }
    const userId = String(claims.sub || '').trim();
    if (!userId) {
      res.status(401).json({ ok: false, code: 'unauthorized', message: 'Invalid session' });
      return null;
    }

    const appSessionVersion = typeof claims.appSessionVersion === 'string' ? claims.appSessionVersion.trim() : '';
    if (!appSessionVersion) {
      res.status(401).json({ ok: false, code: 'unauthorized', message: 'Invalid app session' });
      return null;
    }
    const validated = await ctx.service.validateAppSessionVersion({ userId, appSessionVersion });
    if (!validated.ok) {
      res.status(validated.code === 'internal' ? 500 : 401).json({ ok: false, code: validated.code, message: validated.message });
      return null;
    }

    return { userId, claims };
  }

  async function requirePasskeyStepUp(req: any, res: any, input: { userId: string }): Promise<boolean> {
    const body = req.body || {};
    const challengeId = String(body.stepUpChallengeId ?? body.step_up_challenge_id ?? body.challengeId ?? body.challenge_id ?? '').trim();
    if (!challengeId) {
      res.status(400).json({ ok: false, code: 'invalid_body', message: 'stepUpChallengeId is required' });
      return false;
    }
    const webauthnAuthentication = body.webauthn_authentication ?? body.stepUpWebauthnAuthentication ?? body.step_up_webauthn_authentication;
    if (!webauthnAuthentication || typeof webauthnAuthentication !== 'object') {
      res.status(400).json({ ok: false, code: 'invalid_body', message: 'webauthn_authentication is required for step-up' });
      return false;
    }

    const origin = getOrigin(req.headers);
    const result = await ctx.service.verifyWebAuthnLogin({
      challengeId,
      webauthn_authentication: webauthnAuthentication,
      expected_origin: origin,
    });
    if (!result.ok || !result.verified || !result.userId) {
      res.status(result.code === 'internal' ? 500 : 400).json(result);
      return false;
    }
    if (String(result.userId).trim() !== input.userId) {
      res.status(403).json({ ok: false, code: 'forbidden', message: 'Step-up user mismatch' });
      return false;
    }
    return true;
  }

  router.get('/auth/identities', async (req: any, res: any) => {
    try {
      const sess = await requireAppSession(req, res);
      if (!sess) return;
      const out = await ctx.service.listIdentities({ userId: sess.userId });
      res.status(out.ok ? 200 : (out.code === 'internal' ? 500 : 400)).json(out);
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/auth/link', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const sess = await requireAppSession(req, res);
      if (!sess) return;
      const stepUpOk = await requirePasskeyStepUp(req, res, { userId: sess.userId });
      if (!stepUpOk) return;

      const body = req.body || {};
      const provider = String(body.provider || '').trim();
      const origin = getOrigin(req.headers);

      let subject = '';
      if (provider === 'google') {
        const idToken = String(body.idToken ?? body.id_token ?? '').trim();
        const verified = await ctx.service.verifyGoogleLogin({ idToken });
        if (!verified.ok || !verified.verified || !verified.providerSubject) {
          res.status(verified.code === 'internal' ? 500 : 400).json(verified);
          return;
        }
        subject = verified.providerSubject;
      } else {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'provider must be: google' });
        return;
      }

      const linked = await ctx.service.linkIdentity({ userId: sess.userId, subject, allowMoveIfSoleIdentity: true });
      if (!linked.ok) {
        res.status(linked.code === 'internal' ? 500 : 400).json(linked);
        return;
      }

      const identities = await ctx.service.listIdentities({ userId: sess.userId });
      res.status(200).json({
        ok: true,
        linked: true,
        subject,
        ...(linked.movedFromUserId ? { movedFromUserId: linked.movedFromUserId } : {}),
        ...(identities.ok ? { identities: identities.subjects } : {}),
      });
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/auth/unlink', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const sess = await requireAppSession(req, res);
      if (!sess) return;
      const stepUpOk = await requirePasskeyStepUp(req, res, { userId: sess.userId });
      if (!stepUpOk) return;

      const body = req.body || {};
      const subject = String(body.subject || '').trim();
      if (!subject) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'subject is required' });
        return;
      }
      if (subject.startsWith('near:')) {
        res.status(400).json({ ok: false, code: 'not_supported', message: 'near: subjects cannot be unlinked' });
        return;
      }

      const out = await ctx.service.unlinkIdentity({ userId: sess.userId, subject });
      if (!out.ok) {
        res.status(out.code === 'internal' ? 500 : 400).json(out);
        return;
      }
      const identities = await ctx.service.listIdentities({ userId: sess.userId });

      // Rotate app sessions after unlink to revoke existing sessions bound to removed identities.
      const rotated = await ctx.service.rotateAppSessionVersion({ userId: sess.userId });
      if (!rotated.ok) {
        res.status(rotated.code === 'internal' ? 500 : 400).json({ ok: false, code: rotated.code, message: rotated.message });
        return;
      }

      const session = ctx.opts.session;
      if (session) {
        const authHeader = (req.headers?.authorization || req.headers?.Authorization) as string | undefined;
        const cookieHeader = (req.headers?.cookie || req.headers?.Cookie) as string | undefined;
        const rawKind = (body as any).sessionKind ?? (body as any).session_kind;
        const requestedKind = rawKind === 'cookie' ? 'cookie' : (rawKind === 'jwt' ? 'jwt' : null);
        const inferredKind = requestedKind
          || ((typeof authHeader === 'string' && /^Bearer\s+/i.test(authHeader)) ? 'jwt' : (cookieHeader ? 'cookie' : 'jwt'));

        const preserved: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(sess.claims || {})) {
          if (
            k === 'sub'
            || k === 'exp'
            || k === 'iat'
            || k === 'nbf'
            || k === 'jti'
            || k === 'iss'
            || k === 'aud'
            || k === 'kind'
            || k === 'appSessionVersion'
          ) continue;
          preserved[k] = v;
        }

        const token = await session.signJwt(sess.userId, {
          ...preserved,
          kind: 'app_session_v1',
          appSessionVersion: rotated.appSessionVersion,
        });

        if (inferredKind === 'cookie') {
          res.set('Set-Cookie', session.buildSetCookie(token));
          res.status(200).json({ ok: true, unlinked: true, subject, ...(identities.ok ? { identities: identities.subjects } : {}) });
          return;
        }

        res.status(200).json({ ok: true, unlinked: true, subject, ...(identities.ok ? { identities: identities.subjects } : {}), jwt: token });
        return;
      }

      res.status(200).json({ ok: true, unlinked: true, subject, ...(identities.ok ? { identities: identities.subjects } : {}) });
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  const providers: Record<ProviderId, Record<ActionId, (req: any, res: any) => Promise<void>>> = {
    passkey: {
      options: async (req, res) => {
        if (!req?.body) {
          res.status(400).json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
          return;
        }
        const result = await ctx.service.createWebAuthnLoginOptions(req.body);
        res.status(result.ok ? 200 : (result.code === 'internal' ? 500 : 400)).json(result);
      },
      verify: async (req, res) => {
        if (!req?.body) {
          res.status(400).json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
          return;
        }

        const body = req.body;
        const challengeId = String(body.challengeId ?? body.challenge_id ?? '').trim();
        if (!challengeId) {
          res.status(400).json({ ok: false, code: 'invalid_body', message: 'challengeId is required' });
          return;
        }
        if (!body.webauthn_authentication || typeof body.webauthn_authentication !== 'object') {
          res.status(400).json({ ok: false, code: 'invalid_body', message: 'webauthn_authentication is required' });
          return;
        }

        const origin = getOrigin(req.headers);
        const result = await ctx.service.verifyWebAuthnLogin({
          challengeId,
          webauthn_authentication: body.webauthn_authentication,
          expected_origin: origin,
        });

        if (!result.ok || !result.verified) {
          res.status(result.code === 'internal' ? 500 : 400).json(result);
          return;
        }

        const session = ctx.opts.session;
        if (session && result.userId && result.rpId) {
          try {
            const sessionKind = parseSessionKind(body);
            const ver = await ctx.service.getOrCreateAppSessionVersion({ userId: result.userId });
            if (!ver.ok) throw new Error(ver.message);
            const token = await session.signJwt(result.userId, { kind: 'app_session_v1', rpId: result.rpId, appSessionVersion: ver.appSessionVersion });
            ctx.logger.info(`[relay] creating ${sessionKind === 'cookie' ? 'HttpOnly session' : 'JWT'} for`, result.userId);
            if (sessionKind === 'cookie') {
              res.set('Set-Cookie', session.buildSetCookie(token));
              res.status(200).json({ ok: true, verified: true });
              return;
            }
            res.status(200).json({ ok: true, verified: true, jwt: token });
            return;
          } catch { }
        }

        res.status(200).json({ ok: true, verified: true });
      },
    },
    google: {
      options: async (_req, res) => {
        const configured = ctx.service.isGoogleOidcConfigured();
        res.status(200).json({ ok: true, configured });
      },
      verify: async (req, res) => {
        if (!req?.body) {
          res.status(400).json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
          return;
        }
        const body = req.body || {};
        const idToken = String(body.idToken ?? body.id_token ?? '').trim();
        if (!idToken) {
          res.status(400).json({ ok: false, code: 'invalid_body', message: 'id_token is required' });
          return;
        }

        const result = await ctx.service.verifyGoogleLogin({ idToken });
        if (!result.ok || !result.verified || !result.userId) {
          res.status(result.code === 'internal' ? 500 : 400).json(result);
          return;
        }

        const session = ctx.opts.session;
        if (session) {
          try {
            const sessionKind = parseSessionKind(body);
            const ver = await ctx.service.getOrCreateAppSessionVersion({ userId: result.userId });
            if (!ver.ok) throw new Error(ver.message);
            const token = await session.signJwt(result.userId, {
              kind: 'app_session_v1',
              appSessionVersion: ver.appSessionVersion,
              provider: 'google',
              ...(result.sub ? { googleSub: result.sub } : {}),
              ...(result.email ? { email: result.email } : {}),
              ...(typeof result.emailVerified === 'boolean' ? { emailVerified: result.emailVerified } : {}),
              ...(result.hostedDomain ? { hostedDomain: result.hostedDomain } : {}),
            });
            ctx.logger.info(`[relay] creating ${sessionKind === 'cookie' ? 'HttpOnly session' : 'JWT'} for`, result.userId);
            if (sessionKind === 'cookie') {
              res.set('Set-Cookie', session.buildSetCookie(token));
              res.status(200).json({ ok: true, verified: true, ...(result.email ? { email: result.email } : {}) });
              return;
            }
            res.status(200).json({ ok: true, verified: true, jwt: token, ...(result.email ? { email: result.email } : {}) });
            return;
          } catch { }
        }

        res.status(200).json({ ok: true, verified: true, ...(result.email ? { email: result.email } : {}) });
      },
    },
  };

  router.post('/auth/:provider/:action', async (req: any, res: any) => {
    try {
      const provider = String(req?.params?.provider || '').trim() as ProviderId;
      const action = String(req?.params?.action || '').trim() as ActionId;
      const p = (providers as any)[provider] as Record<ActionId, ((req: any, res: any) => Promise<void>)> | undefined;
      const handler = p ? (p as any)[action] as ((req: any, res: any) => Promise<void>) | undefined : undefined;
      if (!handler) {
        res.status(404).json({ ok: false, code: 'not_found', message: 'Auth route not found' });
        return;
      }
      await handler(req, res);
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}
