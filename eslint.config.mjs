import js from '@eslint/js';
import globals from 'globals';
import prettier from 'eslint-config-prettier';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

export default [
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.next/**',
      '**/.svelte-kit/**',
      '**/.vercel/**',
      '**/.wrangler/**',
      '**/.turbo/**',
      '**/.vitepress/cache/**',
      '**/coverage/**',
      '**/playwright-report/**',
      '**/test-results/**',
      'wasm/**/pkg/**',
      'wasm/**/target/**',
      'examples/tatchi-docs/public/**',
    ],
  },

  js.configs.recommended,

  ...tseslint.configs.recommended,

  {
    files: ['**/*.{js,jsx,mjs,cjs,ts,tsx}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.es2022,
        ...globals.browser,
        ...globals.node,
        ...globals.worker,
      },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      // TS-aware version should apply only to TS files (see TS override).
      '@typescript-eslint/no-unused-vars': 'off',

      // Common, intentional patterns in this repo (e.g. `catch {}` around optional APIs).
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },

  {
    files: ['**/*.{jsx,tsx}'],
    plugins: {
      'react-hooks': reactHooks,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
    },
  },

  {
    files: ['**/*.{ts,tsx}'],
    rules: {
      // TypeScript handles this better than ESLint.
      'no-undef': 'off',

      // Prefer TS-aware version.
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],

      // Too noisy for an existing TS codebase; keep as signal without blocking CI.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-non-null-asserted-optional-chain': 'warn',
      '@typescript-eslint/no-unused-expressions': [
        'error',
        { allowShortCircuit: true, allowTernary: true },
      ],

      // Prefer `@ts-expect-error`, but don't fail the build on existing usage.
      '@typescript-eslint/ban-ts-comment': 'warn',
    },
  },

  {
    files: ['**/*.d.ts'],
    rules: {
      // Declaration files frequently need `any` to model external libs.
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },

  {
    files: ['tests/**/*.{ts,tsx,js,jsx,mjs,cjs}', '**/*.{test,spec}.{ts,tsx,js,jsx,mjs,cjs}'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/ban-ts-comment': 'off',
      '@typescript-eslint/no-unsafe-function-type': 'off',
      'react-hooks/rules-of-hooks': 'off',
      'react-hooks/exhaustive-deps': 'off',
    },
  },

  // Keep ESLint from fighting Prettier.
  prettier,
];
