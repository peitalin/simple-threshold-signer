import { SessionService } from '@tatchi-xyz/sdk/server';
import jwt from 'jsonwebtoken';
// Optional JWT session integration example

type DemoJwtClaims = {
  sub: string;
  iss?: string;
  aud?: string;
  iat?: number;
  exp?: number;
  rpId?: string;
  blockHeight?: number;
};

const demoSecret = 'demo-secret';
const demoIssuer = 'relay-worker-demo';
const demoAudience = 'tatchi-app-demo';
const demoExpiresInSec = 24 * 60 * 60;
const demoCookieName = 'w3a_session';

const jwtSession = new SessionService<DemoJwtClaims>({
  cookie: { name: demoCookieName },
  jwt: {
    signToken: ({ payload }) => {
      // Note: if payload.exp is supplied (e.g., threshold session tokens), do not override it
      // with `expiresIn`, otherwise exp will drift from the server-enforced expiry.
      const hasExp = typeof payload.exp === 'number' && Number.isFinite(payload.exp);
      return jwt.sign(payload, demoSecret, {
        algorithm: 'HS256',
        issuer: demoIssuer,
        audience: demoAudience,
        ...(hasExp ? {} : { expiresIn: demoExpiresInSec }),
      });
    },
    verifyToken: async (token): Promise<{ valid: boolean; payload?: DemoJwtClaims }> => {
      try {
        const payload = jwt.verify(token, demoSecret, {
          algorithms: ['HS256'],
          issuer: demoIssuer,
          audience: demoAudience,
        }) as DemoJwtClaims;
        return { valid: true, payload };
      } catch {
        return { valid: false };
      }
    },
  },
});

export default jwtSession;
