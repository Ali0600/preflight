import tseslint from 'typescript-eslint';

export default tseslint.config(
  // packages/web is a Next.js app — it lints/typechecks via `next build`, not the root config
  // (the base config doesn't parse JSX or know React rules).
  { ignores: ['**/dist/**', '**/node_modules/**', 'packages/web/**'] },
  ...tseslint.configs.recommended,
);
