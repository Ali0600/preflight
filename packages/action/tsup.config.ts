import { defineConfig } from 'tsup';

// A GitHub Action runs from committed code with no install step, so everything — the
// engine and the @actions/* toolkit — must be bundled into one self-contained file.
// CJS is the most battle-tested format for the node24 action runtime.
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs'],
  target: 'node24',
  noExternal: [/.*/], // bundle all deps into dist/index.js
  clean: true,
});
