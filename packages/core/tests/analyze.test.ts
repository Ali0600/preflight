import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { analyzeFiles } from '../src/analyze';
import { setCacheEnabled } from '../src/cache';

beforeEach(() => {
  setCacheEnabled(false);
  // No advisories — we're testing the temp-dir + lockfile-graph plumbing, not OSV.
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ results: [] }), { status: 200 })));
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCacheEnabled(true);
});

describe('analyzeFiles', () => {
  it('resolves the npm lockfile graph from in-memory files (direct + transitive)', async () => {
    const files = {
      'package.json': JSON.stringify({ dependencies: { 'left-pad': '^1.0.0' } }),
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'x' },
          'node_modules/left-pad': { version: '1.3.0' },
          'node_modules/deep-dep': { version: '2.0.0' },
        },
      }),
    };
    const report = await analyzeFiles(files);
    expect(report.findings.find((f) => f.name === 'left-pad')).toMatchObject({
      version: '1.3.0',
      direct: true,
    });
    // the lockfile's transitive entry is picked up too
    expect(report.findings.find((f) => f.name === 'deep-dep')?.direct).toBe(false);
  });

  it('throws when no manifest is among the files', async () => {
    await expect(analyzeFiles({ 'README.md': '# hi' })).rejects.toThrow(/No package\.json/);
  });
});
