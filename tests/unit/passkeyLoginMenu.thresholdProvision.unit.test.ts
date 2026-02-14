import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  passkeyLoginMenu: '/src/components/PasskeyLoginMenu.tsx',
} as const;

type FlowMode = 'register' | 'login';

async function runFlow(
  page: Page,
  args: { flow: FlowMode; cacheHit: boolean },
): Promise<{ provisionCalls: string[]; loggedInCalls: string[] }> {
  return page.evaluate(
    async ({ paths, flow, cacheHit }) => {
      const React =
        ((await import('/node_modules/.vite/deps/react.js').catch(() => null)) as any) ||
        (await import('react'));
      const ReactRuntime = (React as any).default || React;
      const ReactDOMClient =
        ((await import('/node_modules/.vite/deps/react-dom_client.js').catch(() => null)) as any) ||
        (await import('react-dom/client'));
      const ReactDOMClientRuntime = (ReactDOMClient as any).default || ReactDOMClient;
      const ReactDOM =
        ((await import('/node_modules/.vite/deps/react-dom.js').catch(() => null)) as any) ||
        (await import('react-dom'));
      const ReactDOMRuntime = (ReactDOM as any).default || ReactDOM;
      const menuMod = await import(paths.passkeyLoginMenu);
      const PasskeyLoginMenu = (menuMod as any).PasskeyLoginMenu || (menuMod as any).default;
      if (!PasskeyLoginMenu) {
        throw new Error('Failed to load PasskeyLoginMenu module export');
      }

      const counters = {
        provisionCalls: [] as string[],
        loggedInCalls: [] as string[],
      };

      const fakeKeyRef = {
        type: 'threshold-ecdsa-secp256k1',
        userId: 'alice.testnet',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'mock-relayer-key',
        clientVerifyingShareB64u: 'mock-client-share',
      };

      const menuPropsRef: { current: Record<string, unknown> | null } = { current: null };
      const renderErrors: string[] = [];

      function FakePasskeyAuthMenu(props: Record<string, unknown>) {
        menuPropsRef.current = props;
        return ReactRuntime.createElement('div', { id: 'passkey-menu-test-double' });
      }

      class ErrorBoundary extends ReactRuntime.Component<
        { children: React.ReactNode },
        { hasError: boolean }
      > {
        constructor(props: { children: React.ReactNode }) {
          super(props);
          this.state = { hasError: false };
        }

        static getDerivedStateFromError() {
          return { hasError: true };
        }

        componentDidCatch(error: unknown) {
          const message = error instanceof Error ? error.message : String(error || 'unknown error');
          renderErrors.push(message);
        }

        render() {
          if (this.state.hasError) {
            return ReactRuntime.createElement('div', { id: 'passkey-login-menu-render-error' });
          }
          return this.props.children;
        }
      }

      function useTatchiHook() {
        return {
          accountInputState: { targetAccountId: 'alice.testnet', accountExists: true },
          loginAndCreateSession: async () => ({
            success: true,
            nearAccountId: 'alice.testnet',
            jwt: 'mock-jwt-token',
          }),
          registerPasskey: async () => ({
            success: true,
            nearAccountId: 'alice.testnet',
            transactionId: 'mock-registration-tx',
          }),
          tatchi: {},
        };
      }

      const mount = document.createElement('div');
      mount.id = 'passkey-login-menu-threshold-mount';
      document.body.appendChild(mount);

      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(
          ReactRuntime.createElement(
            ErrorBoundary,
            null,
            ReactRuntime.createElement(PasskeyLoginMenu, {
              onLoggedIn: (nearAccountId?: string) => {
                counters.loggedInCalls.push(String(nearAccountId || ''));
              },
              __testOverrides: {
                useTatchiHook,
                useAuthMenuControlHook: () => ({
                  defaultModeOverride: undefined,
                  remountKey: 0,
                  setDefaultModeOverride: () => undefined,
                  bumpRemount: () => undefined,
                  setAndRemount: () => undefined,
                }),
                PasskeyAuthMenuComponent: FakePasskeyAuthMenu,
                readCachedThresholdKeyRef: () => (cacheHit ? (fakeKeyRef as any) : null),
                provisionTempoAndEvmThresholdSigners: async (provisionArgs: {
                  nearAccountId: string;
                }) => {
                  counters.provisionCalls.push(String(provisionArgs.nearAccountId));
                  return {
                    evm: { thresholdEcdsaKeyRef: fakeKeyRef as any },
                    tempo: { thresholdEcdsaKeyRef: fakeKeyRef as any },
                  };
                },
              },
            }),
          ),
        );
      });

      const menuProps = menuPropsRef.current;
      if (!menuProps) {
        const moduleKeys = Object.keys(menuMod || {});
        const html = mount.innerHTML || '';
        throw new Error(
          `PasskeyAuthMenu props were not captured (module keys: ${moduleKeys.join(', ')}; errors: ${renderErrors.join(' | ')}; html: ${html.slice(0, 200)})`,
        );
      }

      if (flow === 'register') {
        const onRegister = menuProps.onRegister as (() => Promise<unknown>) | undefined;
        if (!onRegister) throw new Error('Missing onRegister callback');
        await onRegister();
      } else {
        const onLogin = menuProps.onLogin as (() => Promise<unknown>) | undefined;
        if (!onLogin) throw new Error('Missing onLogin callback');
        await onLogin();
      }

      root.unmount();
      return counters;
    },
    { paths: IMPORT_PATHS, flow: args.flow, cacheHit: args.cacheHit },
  );
}

test.describe('PasskeyLoginMenu threshold signer auto-provision', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('register flow provisions Tempo/EVM signers when cache is missing', async ({ page }) => {
    const result = await runFlow(page, { flow: 'register', cacheHit: false });
    expect(result.provisionCalls).toEqual(['alice.testnet']);
    expect(result.loggedInCalls).toEqual([]);
  });

  test('login flow skips provisioning when both chain keyRefs are already cached', async ({
    page,
  }) => {
    const result = await runFlow(page, { flow: 'login', cacheHit: true });
    expect(result.provisionCalls).toEqual([]);
    expect(result.loggedInCalls).toEqual(['alice.testnet']);
  });

  test('login flow provisions Tempo/EVM signers when cache is missing', async ({ page }) => {
    const result = await runFlow(page, { flow: 'login', cacheHit: false });
    expect(result.provisionCalls).toEqual(['alice.testnet']);
    expect(result.loggedInCalls).toEqual(['alice.testnet']);
  });
});
