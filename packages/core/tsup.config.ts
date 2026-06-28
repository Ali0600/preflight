import { defineConfig } from 'tsup';

// Build the engine to ESM + type declarations so it can be published / reused by the
// Action and web packages. Dev/test/typecheck still resolve the TypeScript source
// directly via the workspace symlink (package `exports` point at ./src), so there is no
// build step in the inner loop — `dist` is only the publishable artifact.
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node18',
  dts: true,
  clean: true,
});
