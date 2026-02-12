// Rolldown config exporting an array of build entries.
import { BUILD_PATHS } from './build-paths.ts';
import * as path from 'path';
import * as fs from 'fs';
import { pathToFileURL } from 'url';

// NOTE: Rolldown's `preserveModulesRoot` is sensitive to relative paths; when it
// can't resolve the root cleanly it will preserve `client/src/...` (or similar)
// into the output. Use absolute roots so dist paths match `sdk/package.json`
// export maps (e.g. `dist/esm/index.js`, `dist/esm/core/...`, `dist/esm/server/...`).
const SDK_ROOT_ABS = process.cwd();
const CLIENT_SRC_ROOT_ABS = path.resolve(SDK_ROOT_ABS, '../client/src');
const CLIENT_REACT_ROOT_ABS = path.resolve(SDK_ROOT_ABS, '../client/src/react');
const CLIENT_INTEGRATIONS_CHAINSIGS_ROOT_ABS = path.resolve(
  SDK_ROOT_ABS,
  '../client/src/integrations/chainsigs',
);
const CLIENT_PLUGINS_ROOT_ABS = path.resolve(SDK_ROOT_ABS, '../client/src/plugins');
const SERVER_SRC_ROOT_ABS = path.resolve(SDK_ROOT_ABS, '../server/src');
const NEAR_SIGNER_WASM_JS_ABS = path.resolve(
  SDK_ROOT_ABS,
  '../wasm/near_signer/pkg/wasm_signer_worker.js',
);
const NEAR_SIGNER_WASM_JS_OUT = 'wasm/near_signer/pkg/wasm_signer_worker.js';

const toPosixPath = (p: string): string => p.split(path.sep).join('/');
const stripExt = (p: string): string => p.replace(/\.[^/.]+$/, '');
const stripLeadingDotDots = (p: string): string => {
  let out = p;
  while (out.startsWith('../')) out = out.slice(3);
  return out;
};
const preservedModuleOut = (opts: { facadeModuleId: string; rootAbs: string; prefix: string }) => {
  const facadeAbs = path.resolve(opts.facadeModuleId);
  if (facadeAbs === NEAR_SIGNER_WASM_JS_ABS) return NEAR_SIGNER_WASM_JS_OUT;

  const rel = toPosixPath(path.relative(opts.rootAbs, facadeAbs));
  const relNoExt = stripExt(stripLeadingDotDots(rel));
  return `${opts.prefix}/${relNoExt}.js`;
};

// Lightweight define plugin to replace process.env.NODE_ENV with 'production' for
// browser/embedded bundles so React and others use prod paths and treeshake well.
const defineNodeEnvPlugin = {
  name: 'define-node-env',
  transform(code: string) {
    if (code && code.includes('process.env.NODE_ENV')) {
      return {
        code: code.replace(/process\.env\.NODE_ENV/g, '"production"'),
        map: null as any,
      };
    }
    return null as any;
  },
};

// Toggle production transforms based on environment
const isProd = process.env.NODE_ENV === 'production';
const prodPlugins = isProd ? [defineNodeEnvPlugin] : [];

const external = [
  // React dependencies
  'react',
  'react-dom',
  'react/jsx-runtime',

  // All @near-js packages
  /@near-js\/.*/,

  // Exclude Lit SSR shim (not needed for client-side only)
  '@lit-labs/ssr-dom-shim',
  // Externalize Lit for library builds so host bundler resolves a single copy
  'lit',
  /lit\/directives\/.*/,
  'lit-html',
  /lit-html\/.*/,

  // Node.js native modules for /server SDK
  'fs',
  'path',
  'url',
  'module',
  'crypto',
  'util',
  // Express-only helpers (optional consumers)
  'express',
  'cors',

  // Node-only database clients (optional consumers)
  'pg',

  // Core dependencies that should be provided by consuming application
  'borsh',
  'bs58',
  '@noble/ed25519',
  'qrcode',
  'jsqr',
  'js-sha256',
  'idb',
  'near-api-js',

  // Optional heavy deps – only used via dynamic imports in chainsigs helper
  'viem',
  'chainsig.js',

  // Other common packages
  'tslib',
  // UI libs used by React components should be provided by the app bundler

  // WASM modules - externalize so bundlers handle them correctly
  /\.wasm$/,
];

// External dependencies for embedded components.
// IMPORTANT: Externalize Lit so the host app's bundler (e.g., Vite) serves a consistent copy.
// Bundling Lit directly into SDK bundles caused internal node_modules paths and ESM export mismatches.
// Embedded bundles are loaded directly in the browser (no bundler/import maps),
// so do NOT externalize dependencies. Bundle everything needed.
const embeddedExternal: (string | RegExp)[] = [];

const aliasConfig = {
  '@build-paths': path.resolve(SDK_ROOT_ABS, 'build-paths.ts'),
  '@/*': path.resolve(SDK_ROOT_ABS, '../client/src/*'),
  '@shared/*': path.resolve(SDK_ROOT_ABS, '../shared/src/*'),
  '@server': path.resolve(SDK_ROOT_ABS, '../server/src/index.ts'),
  '@server/*': path.resolve(SDK_ROOT_ABS, '../server/src/*'),
};

// Static assets expected to be served under `/sdk/*` by hosts.
// Emitting them into dist/esm/sdk ensures deploy steps that rsync the SDK
// directory (often with --delete) keep these files available in production.
const WALLET_SHIM_SOURCE = [
  // Minimal globals used by some deps in browser context
  'window.global ||= window; window.process ||= { env: {} };',
  // Infer absolute SDK base from this script's src and set it for embedded iframes (about:srcdoc)
  '(function(){try{',
  "  var s = (typeof document !== 'undefined' && document.currentScript) ? document.currentScript.src : '';",
  '  if(!s) return;',
  "  var u = new URL(s, (typeof location !== 'undefined' ? location.href : ''));",
  '  var href = u.href;',
  "  var base = href.slice(0, href.lastIndexOf('/') + 1);",
  "  if (typeof window !== 'undefined' && !window.__W3A_WALLET_SDK_BASE__) { window.__W3A_WALLET_SDK_BASE__ = base; }",
  '}catch(e){}})();\n',
].join('\n');
const WALLET_SURFACE_CSS = [
  'html, body { background: transparent !important; margin:0; padding:0; }',
  '',
  // Class-based surface for strict CSP setups (toggled by wallet host bootstrap)
  'html.w3a-transparent, body.w3a-transparent { background: transparent !important; margin:0; padding:0; }',
  '',
  // Minimal portal styles used by confirm-ui (no animation; child components handle transitions)
  '.w3a-portal { position: relative; z-index: 2147483647; opacity: 0; pointer-events: none; }',
  '.w3a-portal.w3a-portal--visible { opacity: 1; pointer-events: auto; }',
  '',
  // Offscreen utility for legacy clipboard fallback (avoids inline styles under strict CSP)
  '.w3a-offscreen { position: fixed; left: -9999px; top: 0; opacity: 0; pointer-events: none; }',
  '',
].join('\n');

const W3A_COMPONENT_HOSTS = [
  'w3a-tx-tree',
  'w3a-drawer',
  'w3a-modal-tx-confirmer',
  'w3a-drawer-tx-confirmer',
  'w3a-tx-confirm-content',
  'w3a-halo-border',
  'w3a-passkey-halo-loading',
] as const;

const emitW3AThemeAliases = (vars: any, indent = '  '): string[] => [
  `${indent}--w3a-colors-textPrimary: ${vars.textPrimary};`,
  `${indent}--w3a-colors-textSecondary: ${vars.textSecondary};`,
  `${indent}--w3a-colors-textMuted: ${vars.textMuted};`,
  `${indent}--w3a-colors-textButton: ${vars.textButton};`,
  `${indent}--w3a-colors-colorBackground: ${vars.colorBackground};`,
  `${indent}--w3a-colors-surface: ${vars.surface};`,
  `${indent}--w3a-colors-surface2: ${vars.surface2};`,
  `${indent}--w3a-colors-surface3: ${vars.surface3};`,
  `${indent}--w3a-colors-surface4: ${vars.surface4};`,
  `${indent}--w3a-colors-primary: ${vars.primary};`,
  `${indent}--w3a-colors-primaryHover: ${vars.primaryHover};`,
  `${indent}--w3a-colors-secondary: ${vars.secondary};`,
  `${indent}--w3a-colors-secondaryHover: ${vars.secondaryHover};`,
  `${indent}--w3a-colors-accent: ${vars.accent};`,
  `${indent}--w3a-colors-buttonBackground: ${vars.buttonBackground};`,
  `${indent}--w3a-colors-buttonHoverBackground: ${vars.buttonHoverBackground};`,
  `${indent}--w3a-colors-hover: ${vars.hover};`,
  `${indent}--w3a-colors-active: ${vars.active};`,
  `${indent}--w3a-colors-focus: ${vars.focus};`,
  `${indent}--w3a-colors-success: ${vars.success};`,
  `${indent}--w3a-colors-warning: ${vars.warning};`,
  `${indent}--w3a-colors-error: ${vars.error};`,
  `${indent}--w3a-colors-info: ${vars.info};`,
  `${indent}--w3a-colors-borderPrimary: ${vars.borderPrimary};`,
  `${indent}--w3a-colors-borderSecondary: ${vars.borderSecondary};`,
  `${indent}--w3a-colors-borderHover: ${vars.borderHover};`,
  `${indent}--w3a-colors-backgroundGradientPrimary: ${vars.backgroundGradientPrimary};`,
  `${indent}--w3a-colors-backgroundGradientSecondary: ${vars.backgroundGradientSecondary};`,
  `${indent}--w3a-colors-backgroundGradient4: ${vars.backgroundGradient4};`,
  `${indent}--w3a-colors-highlightReceiverId: ${vars.highlightReceiverId};`,
  `${indent}--w3a-colors-highlightMethodName: ${vars.highlightMethodName};`,
  `${indent}--w3a-colors-highlightAmount: ${vars.highlightAmount};`,
];

const buildW3AComponentsCss = async (sdkRoot: string): Promise<string> => {
  const palettePath = path.join(sdkRoot, '../client/src/theme/palette.json');
  const paletteRaw = fs.readFileSync(palettePath, 'utf-8');
  const palette = JSON.parse(paletteRaw) as any;

  const baseStylesPath = path.join(sdkRoot, '../client/src/theme/base-styles.js');
  const base = await import(pathToFileURL(baseStylesPath).href);
  const { createThemeTokens } = base as any;
  const {
    DARK_THEME: darkVars,
    LIGHT_THEME: lightVars,
    CREAM_THEME: creamVars,
  } = createThemeTokens(palette);

  const hostSelector = W3A_COMPONENT_HOSTS.join(',\n');
  const lines: string[] = [];

  lines.push(
    '/* Generated from ../client/src/theme/palette.json + ../client/src/theme/base-styles.js. Do not edit by hand. */',
  );
  lines.push(`${hostSelector} {`);
  lines.push(`  --w3a-modal__btn__focus-outline-color: ${darkVars?.focus || '#3b82f6'};`);
  lines.push('  --w3a-tree__file-content__scrollbar-track__background: rgba(255, 255, 255, 0.06);');
  lines.push('  --w3a-tree__file-content__scrollbar-thumb__background: rgba(255, 255, 255, 0.22);');

  const pushScale = (name: string, scale: Record<string, string>) => {
    Object.keys(scale || {}).forEach((k) => {
      lines.push(`  --w3a-${name}${k}: ${scale[k]};`);
    });
  };

  pushScale('grey', palette.grey || {});
  pushScale('slate', palette.slate || {});
  pushScale('cream', palette.cream || {});

  const exclude = new Set(['grey', 'slate', 'cream', 'gradients', 'tokens', 'themes']);
  Object.keys(palette)
    .filter((k) => !exclude.has(k))
    .forEach((fam) => {
      if (palette[fam] && typeof palette[fam] === 'object') pushScale(fam, palette[fam]);
    });

  Object.keys(palette.gradients || {}).forEach((name) => {
    lines.push(`  --w3a-gradient-${name}: ${palette.gradients[name]};`);
  });

  lines.push('');
  lines.push('  /* Default token aliases (dark) for hosts */');
  lines.push(...emitW3AThemeAliases(darkVars));
  lines.push('}');

  lines.push('');
  lines.push(':root {');
  lines.push(...emitW3AThemeAliases(darkVars, '  '));
  lines.push('}');
  lines.push('');
  lines.push(':root[data-w3a-theme="light"] {');
  lines.push(...emitW3AThemeAliases(lightVars, '  '));
  lines.push('}');
  lines.push('');
  lines.push(':root[data-w3a-theme="cream"] {');
  lines.push(...emitW3AThemeAliases(creamVars, '  '));
  lines.push('}');

  const themedSelLight = W3A_COMPONENT_HOSTS.map((s) => `:root[data-w3a-theme="light"] ${s}`).join(
    ',\n',
  );
  const themedSelCream = W3A_COMPONENT_HOSTS.map((s) => `:root[data-w3a-theme="cream"] ${s}`).join(
    ',\n',
  );

  lines.push('');
  lines.push(`${themedSelLight} {`);
  lines.push(...emitW3AThemeAliases(lightVars, '  '));
  lines.push('}');
  lines.push('');
  lines.push(`${themedSelCream} {`);
  lines.push(...emitW3AThemeAliases(creamVars, '  '));
  lines.push('}');

  return `${lines.join('\n')}\n`;
};

const emitWalletServiceStaticAssets = async (sdkRoot = process.cwd()): Promise<void> => {
  const sdkDir = path.join(sdkRoot, `${BUILD_PATHS.BUILD.ESM}/sdk`);
  fs.mkdirSync(sdkDir, { recursive: true });

  const writeFileIfMissing = (filePath: string, contents: string) => {
    if (!fs.existsSync(filePath)) fs.writeFileSync(filePath, contents, 'utf-8');
  };

  const copyIfMissing = (src: string, dest: string) => {
    if (fs.existsSync(src) && !fs.existsSync(dest)) fs.copyFileSync(src, dest);
  };

  writeFileIfMissing(path.join(sdkDir, 'wallet-shims.js'), WALLET_SHIM_SOURCE);
  writeFileIfMissing(path.join(sdkDir, 'wallet-service.css'), WALLET_SURFACE_CSS);

  try {
    const w3aComponentsCss = await buildW3AComponentsCss(sdkRoot);
    fs.writeFileSync(path.join(sdkDir, 'w3a-components.css'), w3aComponentsCss, 'utf-8');
  } catch (e) {
    console.warn('⚠️  Failed to generate w3a-components.css from palette:', e);
    const src = path.join(
      sdkRoot,
      '../client/src/core/signing/secureConfirm/ui/lit-components/css/w3a-components.css',
    );
    const dest = path.join(sdkDir, 'w3a-components.css');
    if (fs.existsSync(src)) fs.copyFileSync(src, dest);
  }

  copyIfMissing(
    path.join(sdkRoot, '../client/src/core/signing/secureConfirm/ui/lit-components/css/tx-tree.css'),
    path.join(sdkDir, 'tx-tree.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, '../client/src/core/signing/secureConfirm/ui/lit-components/css/tx-confirmer.css'),
    path.join(sdkDir, 'tx-confirmer.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, '../client/src/core/signing/secureConfirm/ui/lit-components/css/drawer.css'),
    path.join(sdkDir, 'drawer.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, '../client/src/core/signing/secureConfirm/ui/lit-components/css/halo-border.css'),
    path.join(sdkDir, 'halo-border.css'),
  );
  copyIfMissing(
    path.join(
      sdkRoot,
      '../client/src/core/signing/secureConfirm/ui/lit-components/css/passkey-halo-loading.css',
    ),
    path.join(sdkDir, 'passkey-halo-loading.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, '../client/src/core/signing/secureConfirm/ui/lit-components/css/padlock-icon.css'),
    path.join(sdkDir, 'padlock-icon.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, '../client/src/core/signing/secureConfirm/ui/lit-components/css/export-viewer.css'),
    path.join(sdkDir, 'export-viewer.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, '../client/src/core/signing/secureConfirm/ui/lit-components/css/export-iframe.css'),
    path.join(sdkDir, 'export-iframe.css'),
  );
  copyIfMissing(
    path.join(sdkRoot, '../client/src/core/WalletIframe/client/overlay/overlay.css'),
    path.join(sdkDir, 'overlay.css'),
  );

  console.log('✅ Emitted /sdk wallet-shims.js and wallet-service.css');
};

const emitWalletServiceStaticPlugin = {
  name: 'emit-wallet-service-static',
  async generateBundle() {
    try {
      await emitWalletServiceStaticAssets();
    } catch (err) {
      console.warn('⚠️  Unable to emit wallet static assets:', err);
    }
  },
};

const copyWasmAsset = (source: string, destination: string, label: string): void => {
  if (!fs.existsSync(source)) {
    throw new Error(`Missing WASM source at ${source}`);
  }
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
  console.log(label);
};

const configs = [
  // ESM build
  {
    input: [
      '../client/src/index.ts',
      // Treat this as an entry so Rolldown doesn't tree-shake its re-exported WASM enums.
      // Tests (and some internal tools) import `core/types/signer-worker` directly.
      '../client/src/core/types/signer-worker.ts',
    ],
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: CLIENT_SRC_ROOT_ABS,
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // Server ESM build
  {
    input: '../server/src/index.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: SERVER_SRC_ROOT_ABS,
      entryFileNames: (chunk) => {
        if (!chunk.facadeModuleId) return `server/${chunk.name}.js`;
        return preservedModuleOut({
          facadeModuleId: chunk.facadeModuleId,
          rootAbs: SERVER_SRC_ROOT_ABS,
          prefix: 'server',
        });
      },
      chunkFileNames: (chunk) => {
        if (!chunk.facadeModuleId) return `server/${chunk.name}.js`;
        return preservedModuleOut({
          facadeModuleId: chunk.facadeModuleId,
          rootAbs: SERVER_SRC_ROOT_ABS,
          prefix: 'server',
        });
      },
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // Plugins: headers helper ESM
  {
    input: '../client/src/plugins/headers.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'plugins/headers.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // Plugins: Next helper ESM
  {
    input: '../client/src/plugins/next.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'plugins/next.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // Express router helper ESM bundle
  {
    input: '../server/src/router/express-adaptor.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'server/router/express.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // Cloudflare Workers router adaptor ESM bundle
  {
    input: '../server/src/router/cloudflare-adaptor.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'server/router/cloudflare.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // WASM signer re-export ESM
  {
    input: '../server/src/wasm/signer.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'server/wasm/signer.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // React ESM build
  {
    input: [
      '../client/src/react/index.ts',
      // Ensure public subpath entrypoints exist in dist even when re-exports are flattened.
      '../client/src/react/components/PasskeyAuthMenu/passkeyAuthMenuCompat.ts',
      // Public subpath entrypoints (avoid treeshaking away default exports).
      '../client/src/react/components/PasskeyAuthMenu/preload.ts',
      '../client/src/react/components/PasskeyAuthMenu/shell.tsx',
      '../client/src/react/components/PasskeyAuthMenu/skeleton.tsx',
      '../client/src/react/components/PasskeyAuthMenu/client.tsx',
    ],
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: CLIENT_REACT_ROOT_ABS,
      entryFileNames: (chunk) => {
        if (!chunk.facadeModuleId) return `react/${chunk.name}.js`;
        return preservedModuleOut({
          facadeModuleId: chunk.facadeModuleId,
          rootAbs: CLIENT_REACT_ROOT_ABS,
          prefix: 'react',
        });
      },
      chunkFileNames: (chunk) => {
        if (!chunk.facadeModuleId) return `react/${chunk.name}.js`;
        return preservedModuleOut({
          facadeModuleId: chunk.facadeModuleId,
          rootAbs: CLIENT_REACT_ROOT_ABS,
          prefix: 'react',
        });
      },
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // Chainsigs helper ESM build
  {
    input: '../client/src/integrations/chainsigs/index.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: CLIENT_INTEGRATIONS_CHAINSIGS_ROOT_ABS,
      entryFileNames: 'chainsigs/[name].js',
      chunkFileNames: 'chainsigs/[name].js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // Shared utils needed in-browser by some test harnesses (served under `/sdk/esm/*`).
  {
    input: '../shared/src/utils/base64.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'utils/base64.js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
  // React CSS build - output to separate styles directory to avoid JS conflicts
  {
    input: '../client/src/react/styles.css',
    output: {
      dir: `${BUILD_PATHS.BUILD.ESM}/react/styles`,
      format: 'esm',
      assetFileNames: 'styles.css',
    },
  },
  // WASM Signer Worker build for server usage - includes WASM binary
  {
    input: '../wasm/near_signer/pkg/wasm_signer_worker.js',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'wasm/near_signer/pkg/wasm_signer_worker.js',
    },
    plugins: [
      {
        name: 'emit-near-signer-wasm',
        generateBundle() {
          try {
            const source = fs.readFileSync(
              path.join(SDK_ROOT_ABS, '../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm'),
            );
            (this as any).emitFile({
              type: 'asset',
              fileName: 'wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
              source,
            });
            console.log('✅ Emitted dist/esm/wasm/near_signer/pkg/wasm_signer_worker_bg.wasm');
          } catch (error) {
            console.error('❌ Failed to copy signer WASM asset:', error);
            throw error;
          }
        },
      },
    ],
  },
  // Confirm UI helpers and elements bundle for iframe usage
  // Build from confirm-ui.ts (container-agnostic); keep output filename stable
  {
    input: '../client/src/core/signing/secureConfirm/ui/lit-components/confirm-ui.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'sdk/tx-confirm-ui.js',
      chunkFileNames: 'sdk/[name]-[hash].js',
    },
    external: embeddedExternal,
    resolve: {
      alias: aliasConfig,
    },
    // Minification is controlled via CLI flags; no config option in current Rolldown types
    plugins: prodPlugins,
  },
  // Wallet iframe host + confirmer bundles
  {
    input: {
      // Tx Confirmer component
      'w3a-tx-confirmer':
        '../client/src/core/signing/secureConfirm/ui/lit-components/IframeTxConfirmer/tx-confirmer-wrapper.ts',
      // Wallet service host (headless)
      'wallet-iframe-host-runtime': '../client/src/core/WalletIframe/host/index.ts',
      // Export viewer host + bootstrap
      'iframe-export-bootstrap':
        '../client/src/core/signing/secureConfirm/ui/lit-components/ExportPrivateKey/iframe-export-bootstrap-script.ts',
    },
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'sdk/[name].js',
      chunkFileNames: 'sdk/[name]-[hash].js',
    },
    external: embeddedExternal,
    resolve: {
      alias: aliasConfig,
    },
    // Minification is controlled via CLI flags; no config option in current Rolldown types
    plugins: [...prodPlugins, emitWalletServiceStaticPlugin],
  },
  // Export Private Key viewer bundle (Lit element rendered inside iframe)
  {
    input: '../client/src/core/signing/secureConfirm/ui/lit-components/ExportPrivateKey/viewer.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'sdk/export-private-key-viewer.js',
      chunkFileNames: 'sdk/[name]-[hash].js',
    },
    external: embeddedExternal,
    resolve: {
      alias: aliasConfig,
    },
    // Minification is controlled via CLI flags; no config option in current Rolldown types
    plugins: prodPlugins,
  },
  // Standalone bundles for HaloBorder + PasskeyHaloLoading (for iframe/embedded usage)
  {
    input: {
      'halo-border': '../client/src/core/signing/secureConfirm/ui/lit-components/HaloBorder/index.ts',
      'passkey-halo-loading':
        '../client/src/core/signing/secureConfirm/ui/lit-components/PasskeyHaloLoading/index.ts',
    },
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      entryFileNames: 'sdk/[name].js',
      chunkFileNames: 'sdk/[name]-[hash].js',
    },
    external: embeddedExternal,
    resolve: {
      alias: aliasConfig,
    },
    // Minification is controlled via CLI flags; no config option in current Rolldown types
    plugins: prodPlugins,
  },
  // Vite plugin ESM build (source moved to src/plugins)
  {
    input: '../client/src/plugins/vite.ts',
    output: {
      dir: BUILD_PATHS.BUILD.ESM,
      format: 'esm',
      preserveModules: true,
      preserveModulesRoot: CLIENT_PLUGINS_ROOT_ABS,
      entryFileNames: 'plugins/[name].js',
      chunkFileNames: 'plugins/[name].js',
      sourcemap: true,
    },
    external,
    resolve: {
      alias: aliasConfig,
    },
  },
] satisfies import('rolldown').RolldownOptions[];

export default configs;
