import { defineConfig } from 'tsup';

// Bundle the CLI into a single standalone ESM file so `npx @preflight/cli` runs without
// tsx. `@preflight/core` is inlined (noExternal) — the published CLI then only needs its
// real runtime deps (commander, picocolors), which stay external. The shebang in
// src/index.ts is preserved and tsup marks the output executable.
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node18',
  noExternal: ['@preflight/core'],
  clean: true,
});
