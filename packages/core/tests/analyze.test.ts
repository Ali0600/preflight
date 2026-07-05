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
    expect(report.lockfile).toBe(true);
  });

  it('throws when no manifest is among the files', async () => {
    await expect(analyzeFiles({ 'README.md': '# hi' })).rejects.toThrow(/No package\.json/);
  });

  it('rejects a key that escapes the temp dir — path traversal (#2)', async () => {
    await expect(
      analyzeFiles({ '../evil.txt': 'pwned', 'package.json': '{}' }),
    ).rejects.toThrow(/Unsafe file path/);
    await expect(analyzeFiles({ '../../etc/x': 'pwned' })).rejects.toThrow(/Unsafe file path/);
  });

  it('allows a legitimate sub-path inside the sandbox', async () => {
    const report = await analyzeFiles({
      'backend/package.json': JSON.stringify({ dependencies: {} }),
    });
    expect(report.total).toBe(0); // resolved & analyzed, no traversal
  });

  it('flags a lockfile-less npm scan (direct deps only) so callers can warn (#23)', async () => {
    const report = await analyzeFiles({
      'package.json': JSON.stringify({ dependencies: { 'left-pad': '1.3.0' } }),
    });
    expect(report.lockfile).toBe(false);
  });

  it('react next to `next` (no expo) is not framework-pinned (#18)', async () => {
    const files = {
      'package.json': JSON.stringify({ dependencies: { next: '^16.0.0', react: '^19.0.0' } }),
    };
    const report = await analyzeFiles(files);
    expect(report.findings.find((f) => f.name === 'next')?.verdict).toBe('pinned');
    const react = report.findings.find((f) => f.name === 'react')!;
    expect(react.lockstep.pinned).toBe(false);
    expect(react.verdict).toBe('safe');

    // ...but react next to `expo` is still Expo-coordinated
    const expoReport = await analyzeFiles({
      'package.json': JSON.stringify({ dependencies: { expo: '^56.0.0', react: '^19.0.0' } }),
    });
    expect(expoReport.findings.find((f) => f.name === 'react')?.lockstep).toMatchObject({
      pinned: true,
      framework: 'Expo',
    });
  });
});

describe('analyzeFiles — runtime target', () => {
  it('attaches runtimeCompat and the incompatible verdict end-to-end (pip on Python 3.9)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('pypi.org/pypi/uvicorn')) {
          return new Response(
            JSON.stringify({
              info: { version: '0.49.0' },
              releases: {
                '0.39.0': [{ filename: 'u.whl', requires_python: '>=3.9', yanked: false }],
                '0.49.0': [{ filename: 'u.whl', requires_python: '>=3.10', yanked: false }],
              },
            }),
            { status: 200 },
          );
        }
        return new Response(JSON.stringify({ results: [] }), { status: 200 }); // OSV
      }),
    );
    const report = await analyzeFiles(
      { 'requirements.txt': 'uvicorn>=0.49\n' },
      {
        runtimes: {
          python: { runtime: 'python', version: '3.9', source: '--python flag', explicit: true },
        },
      },
    );
    expect(report.runtimeTarget?.version).toBe('3.9');
    expect(report.summary.incompatible).toBe(1);
    const f = report.findings.find((x) => x.name === 'uvicorn');
    expect(f?.verdict).toBe('incompatible');
    expect(f?.runtimeCompat?.maxCompatible).toBe('0.39.0');
    expect(f?.reason).toContain('max compatible 0.39.0');
  });

  it('no target for the manifest ecosystem -> no runtime fetch, no runtimeCompat', async () => {
    const report = await analyzeFiles(
      { 'requirements.txt': 'uvicorn>=0.49\n' },
      { runtimes: { node: { runtime: 'node', version: '18', source: '.nvmrc', explicit: false } } },
    );
    expect(report.runtimeTarget).toBeUndefined();
    expect(report.findings[0]?.runtimeCompat).toBeUndefined();
  });
});
