import { TatchiPasskey } from '@tatchi-xyz/sdk';
import { ActionType } from '@tatchi-xyz/sdk';

type Elements = {
  relayerUrl: HTMLInputElement;
  walletOrigin: HTMLInputElement;
  nearRpcUrl: HTMLInputElement;
  contractId: HTMLInputElement;
  nearAccountId: HTMLInputElement;
  receiverId: HTMLInputElement;
  log: HTMLTextAreaElement;
  init: HTMLButtonElement;
  register: HTMLButtonElement;
  login: HTMLButtonElement;
  send: HTMLButtonElement;
  clear: HTMLButtonElement;
};

function mustGetInput(id: string): HTMLInputElement {
  const el = document.getElementById(id);
  if (!(el instanceof HTMLInputElement)) throw new Error(`Missing input #${id}`);
  return el;
}

function mustGetButton(id: string): HTMLButtonElement {
  const el = document.getElementById(id);
  if (!(el instanceof HTMLButtonElement)) throw new Error(`Missing button #${id}`);
  return el;
}

function mustGetTextarea(id: string): HTMLTextAreaElement {
  const el = document.getElementById(id);
  if (!(el instanceof HTMLTextAreaElement)) throw new Error(`Missing textarea #${id}`);
  return el;
}

function nowIso(): string {
  return new Date().toISOString().replace('T', ' ').replace('Z', '');
}

function formatError(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err || 'Unknown error');
}

function normalizeUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  try {
    const url = new URL(trimmed);
    return url.toString().replace(/\/$/, '');
  } catch {
    return trimmed.replace(/\/$/, '');
  }
}

function createLogger(textarea: HTMLTextAreaElement) {
  return (message: string, data?: unknown) => {
    const line = data === undefined ? message : `${message} ${safeStringify(data)}`;
    const next = `[${nowIso()}] ${line}`.trim();
    textarea.value = textarea.value ? `${textarea.value}\n${next}` : next;
    textarea.scrollTop = textarea.scrollHeight;
  };
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function setBusy(els: Elements, busy: boolean) {
  els.init.disabled = busy;
  els.register.disabled = busy;
  els.login.disabled = busy;
  els.send.disabled = busy;
}

function readConfig(els: Elements) {
  const relayerUrl = normalizeUrl(els.relayerUrl.value);
  const walletOrigin = normalizeUrl(els.walletOrigin.value);
  const nearRpcUrl = els.nearRpcUrl.value.trim();
  const contractId = els.contractId.value.trim();
  const nearAccountId = els.nearAccountId.value.trim();
  const receiverId = (els.receiverId.value.trim() || nearAccountId).trim();

  if (!relayerUrl) throw new Error('Missing relayer URL');
  if (!walletOrigin) throw new Error('Missing wallet origin');
  if (!nearRpcUrl) throw new Error('Missing NEAR RPC URL');
  if (!contractId) throw new Error('Missing contract ID');
  if (!nearAccountId) throw new Error('Missing NEAR account ID');

  return { relayerUrl, walletOrigin, nearRpcUrl, contractId, nearAccountId, receiverId };
}

function createTatchi(cfg: ReturnType<typeof readConfig>): TatchiPasskey {
  return new TatchiPasskey({
    nearNetwork: 'testnet',
    nearRpcUrl: cfg.nearRpcUrl,
    contractId: cfg.contractId,
    signerMode: { mode: 'threshold-signer', behavior: 'strict' },
    signingSessionDefaults: {
      ttlMs: 5 * 60_000,
      remainingUses: 3,
    },
    relayer: {
      url: cfg.relayerUrl,
    },
    iframeWallet: {
      walletOrigin: cfg.walletOrigin,
      walletServicePath: '/wallet-service',
      sdkBasePath: '/sdk',
      // Allows a single passkey to be usable across example.localhost + wallet.example.localhost.
      rpIdOverride: 'example.localhost',
    },
  });
}

function main() {
  const els: Elements = {
    relayerUrl: mustGetInput('relayerUrl'),
    walletOrigin: mustGetInput('walletOrigin'),
    nearRpcUrl: mustGetInput('nearRpcUrl'),
    contractId: mustGetInput('contractId'),
    nearAccountId: mustGetInput('nearAccountId'),
    receiverId: mustGetInput('receiverId'),
    log: mustGetTextarea('log'),
    init: mustGetButton('init'),
    register: mustGetButton('register'),
    login: mustGetButton('login'),
    send: mustGetButton('send'),
    clear: mustGetButton('clear'),
  };

  els.relayerUrl.value = 'https://relay-server2.localhost';
  els.walletOrigin.value = 'https://wallet.example.localhost';
  els.nearRpcUrl.value = 'https://test.rpc.fastnear.com';
  els.contractId.value = 'w3a-v1.testnet';

  const log = createLogger(els.log);

  let tatchi: TatchiPasskey | null = null;

  const getTatchi = () => {
    const cfg = readConfig(els);
    if (!tatchi) {
      tatchi = createTatchi(cfg);
      log('Created TatchiPasskey', {
        relayerUrl: cfg.relayerUrl,
        walletOrigin: cfg.walletOrigin,
        nearRpcUrl: cfg.nearRpcUrl,
        contractId: cfg.contractId,
      });
    }
    return { cfg, tatchi };
  };

  els.clear.addEventListener('click', (e) => {
    e.preventDefault();
    els.log.value = '';
  });

  els.init.addEventListener('click', async (e) => {
    e.preventDefault();
    setBusy(els, true);
    try {
      const { cfg, tatchi } = getTatchi();
      log('Init wallet iframe…');
      await tatchi.initWalletIframe(cfg.nearAccountId);
      log('Wallet iframe ready');
    } catch (err) {
      log('Init failed:', { error: formatError(err) });
    } finally {
      setBusy(els, false);
    }
  });

  els.register.addEventListener('click', async (e) => {
    e.preventDefault();
    setBusy(els, true);
    try {
      const { cfg, tatchi } = getTatchi();
      log(`Register (threshold) for ${cfg.nearAccountId}…`);
      const res = await tatchi.registerPasskey(cfg.nearAccountId, {
        signerMode: { mode: 'threshold-signer', behavior: 'strict' },
        onEvent: (ev) => log(`[register] ${ev.phase} ${ev.status}: ${ev.message}`),
        onError: (err) => log('[register] error', { error: err.message }),
      });
      log('Register result:', res);
    } catch (err) {
      log('Register failed:', { error: formatError(err) });
    } finally {
      setBusy(els, false);
    }
  });

  els.login.addEventListener('click', async (e) => {
    e.preventDefault();
    setBusy(els, true);
    try {
      const { cfg, tatchi } = getTatchi();
      log(`Login for ${cfg.nearAccountId}…`);
      const res = await tatchi.loginAndCreateSession(cfg.nearAccountId, {
        signingSession: { ttlMs: 5 * 60_000, remainingUses: 3 },
        onEvent: (ev) => log(`[login] ${ev.phase} ${ev.status}: ${ev.message}`),
        onError: (err) => log('[login] error', { error: err.message }),
      });
      log('Login result:', res);
    } catch (err) {
      log('Login failed:', { error: formatError(err) });
    } finally {
      setBusy(els, false);
    }
  });

  els.send.addEventListener('click', async (e) => {
    e.preventDefault();
    setBusy(els, true);
    try {
      const { cfg, tatchi } = getTatchi();
      log(`Send 1 yocto transfer: ${cfg.nearAccountId} → ${cfg.receiverId}…`);
      const res = await tatchi.signAndSendTransaction({
        nearAccountId: cfg.nearAccountId,
        receiverId: cfg.receiverId,
        actions: [{ type: ActionType.Transfer, amount: '1' }],
        options: {
          signerMode: { mode: 'threshold-signer', behavior: 'strict' },
          onEvent: (ev) => log(`[tx] ${ev.phase} ${ev.status}: ${ev.message}`),
          onError: (err) => log('[tx] error', { error: err.message }),
          waitUntil: 'EXECUTED_OPTIMISTIC',
        },
      });
      log('Tx result:', res);
    } catch (err) {
      log('Tx failed:', { error: formatError(err) });
    } finally {
      setBusy(els, false);
    }
  });

  log('Open this page at https://example.localhost/demo.html when running Caddy.');
}

main();

