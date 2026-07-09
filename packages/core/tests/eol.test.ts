import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setCacheEnabled } from '../src/cache';
import { cycleOf, fetchRuntimeEol } from '../src/eol';
import type { RuntimeTarget } from '../src/types';

const target = (runtime: 'node' | 'python', version: string): RuntimeTarget => ({
  runtime,
  version,
  source: 'test',
  explicit: true,
});

const soon = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

// Shape as served by endoflife.date (verified live 2026-07-09).
const NODE_CYCLES = [
  { cycle: '22', releaseDate: '2024-04-24', eol: '2027-04-30', latest: '22.23.1', lts: '2024-10-29' },
  { cycle: '20', releaseDate: '2023-04-18', eol: soon, latest: '20.19.5', lts: '2023-10-24' },
  { cycle: '18', releaseDate: '2022-04-19', eol: '2025-04-30', latest: '18.20.8', lts: '2022-10-25' },
];
const PYTHON_CYCLES = [
  { cycle: '3.13', eol: '2029-10-31', latest: '3.13.14' },
  { cycle: '3.9', eol: '2025-10-31', latest: '3.9.24' },
  { cycle: '2.7', eol: true, latest: '2.7.18' }, // boolean form: already EOL, no date
];

beforeEach(() => {
  setCacheEnabled(false);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      if (url.endsWith('/nodejs.json')) return new Response(JSON.stringify(NODE_CYCLES), { status: 200 });
      if (url.endsWith('/python.json')) return new Response(JSON.stringify(PYTHON_CYCLES), { status: 200 });
      return new Response('nope', { status: 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCacheEnabled(true);
});

describe('cycleOf', () => {
  it('maps Node versions to their major cycle and Python to major.minor', () => {
    expect(cycleOf('node', '18')).toBe('18');
    expect(cycleOf('node', '18.19.0')).toBe('18');
    expect(cycleOf('python', '3.9')).toBe('3.9');
    expect(cycleOf('python', '3.9.18')).toBe('3.9');
  });
  it('refuses to guess for a bare Python major', () => {
    expect(cycleOf('python', '3')).toBeUndefined();
  });
});

describe('fetchRuntimeEol', () => {
  it('flags a past-EOL Node cycle', async () => {
    const e = await fetchRuntimeEol(target('node', '18'));
    expect(e?.isEol).toBe(true);
    expect(e?.eol).toBe('2025-04-30');
    expect(e?.daysUntilEol).toBeLessThan(0);
  });

  it('reports a supported cycle with its future EOL date', async () => {
    const e = await fetchRuntimeEol(target('node', '22.1.0'));
    expect(e?.isEol).toBe(false);
    expect(e?.eol).toBe('2027-04-30');
    expect(e?.daysUntilEol).toBeGreaterThan(90);
  });

  it('computes days for an EOL-soon cycle', async () => {
    const e = await fetchRuntimeEol(target('node', '20'));
    expect(e?.isEol).toBe(false);
    expect(e?.daysUntilEol).toBeGreaterThan(0);
    expect(e?.daysUntilEol).toBeLessThanOrEqual(90);
  });

  it('treats boolean eol: true as already end-of-life (no date)', async () => {
    const e = await fetchRuntimeEol(target('python', '2.7'));
    expect(e?.isEol).toBe(true);
    expect(e?.eol).toBeUndefined();
  });

  it('returns undefined for an unknown cycle rather than guessing', async () => {
    expect(await fetchRuntimeEol(target('node', '99'))).toBeUndefined();
  });

  it('degrades (announced) on a failed fetch and treats an empty list as failure', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 500 })));
    let sources: string[] = [];
    expect(await fetchRuntimeEol(target('node', '18'), (s) => sources.push(s))).toBeUndefined();
    expect(sources).toEqual(['endoflife.date']);

    vi.stubGlobal('fetch', vi.fn(async () => new Response('[]', { status: 200 })));
    sources = [];
    expect(await fetchRuntimeEol(target('node', '18'), (s) => sources.push(s))).toBeUndefined();
    expect(sources).toEqual(['endoflife.date']);
  });

  it('does NOT cache a failure — the next call retries and can succeed', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'preflight-eol-test-'));
    const prev = process.env.PREFLIGHT_CACHE_DIR;
    process.env.PREFLIGHT_CACHE_DIR = dir;
    setCacheEnabled(true);
    try {
      let calls = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn(async () => {
          calls += 1;
          if (calls === 1) return new Response('down', { status: 503 });
          return new Response(JSON.stringify(NODE_CYCLES), { status: 200 });
        }),
      );
      expect(await fetchRuntimeEol(target('node', '18'))).toBeUndefined(); // failure, not cached
      const e = await fetchRuntimeEol(target('node', '18')); // retried, succeeds
      expect(e?.isEol).toBe(true);
      expect(calls).toBe(2);
    } finally {
      process.env.PREFLIGHT_CACHE_DIR = prev;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
