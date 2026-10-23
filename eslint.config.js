// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

const restrictImports = (...patterns) => ({
  '@typescript-eslint/no-restricted-imports': ['error', { patterns }],
});

// The protocol layer takes a `ByteSocket` and names no runtime, and its only
// cryptography is WebCrypto. That is what lets the transport, the channels and
// SFTP be tested against in-memory streams and run in Node and workerd alike.
const runtimeFree = {
  regex: '^(cloudflare:|node:|bun:|deno)',
  message: 'Only src/workers/ may name a runtime; everything else takes a ByteSocket.',
};

const noModuleState = [
  'Program > VariableDeclaration[kind="let"]',
  'Program > ExportNamedDeclaration > VariableDeclaration[kind="let"]',
].map((selector) => ({
  selector,
  message: 'No module-level mutable state: one isolate serves many requests.',
}));

export default tseslint.config(
  { ignores: ['**/node_modules/', '**/.wrangler/', '.cache/'] },
  js.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      'max-lines': ['error', { max: 300, skipBlankLines: true, skipComments: true }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['**/*.{js,mjs}'],
    extends: [tseslint.configs.disableTypeChecked],
  },
  {
    files: ['src/**/*.ts'],
    ignores: ['src/workers/**/*.ts'],
    rules: {
      ...restrictImports(runtimeFree),
      'no-restricted-syntax': ['error', ...noModuleState],
    },
  },
);
