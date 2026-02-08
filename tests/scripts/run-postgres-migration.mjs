import dotenv from 'dotenv';
import { ensurePostgresSchema } from '../../sdk/dist/esm/server/storage/postgres.js';

const envFile = String(process.env.ENV_FILE || './examples/relay-server/.env').trim();
dotenv.config({ path: envFile });

const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
if (!postgresUrl) {
  throw new Error(`POSTGRES_URL missing (loaded ENV_FILE=${envFile})`);
}

await ensurePostgresSchema({ postgresUrl, logger: console });
console.log('[migration] postgres schema ready');

