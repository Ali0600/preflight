import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setCacheEnabled } from '../src/cache';
import { fetchDownloads } from '../src/downloads';

// Shapes verified live (2026-07-09): bulk keyed by name, single/scoped flat, pypistats data.last_week.
let calls: string[] = [];

beforeEach(() => {
  setCacheEnabled(false);
  calls = [];
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCacheEnabled(true);
});

function stub(handler: (url: string) => Response | Promise<Response>): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      calls.push(url);
      return handler(url);
    }),
  );
}

describe('fetchDownloads (npm)', () => {
  it('bulk-fetches unscoped names in chunks of 128', async () => {
    const names = Array.from({ length: 129 }, (_, i) => `pkg-${i}`);
    stub((url) => {
      const listed = decodeURIComponent(url.split('/').pop()!).split(',');
      const body = Object.fromEntries(listed.map((n) => [n, { downloads: 7, package: n }]));
      // A 1-name request returns the flat single shape — mimic the real API.
      return new Response(
        JSON.stringify(listed.length === 1 ? { downloads: 7, package: listed[0] } : body),
        { status: 200 },
      );
    });
    const out = await fetchDownloads(names, 'npm');
    expect(calls.length).toBe(2); // 128 + 1
    expect(out.size).toBe(129);
    expect(out.get('pkg-128')).toBe(7);
  });

  it('fetches scoped packages individually (bulk does not accept them)', async () => {
    stub((url) => {
      expect(url).toContain(encodeURIComponent('@types/node'));
      return new Response(JSON.stringify({ downloads: 366424234, package: '@types/node' }), { status: 200 });
    });
    const out = await fetchDownloads(['@types/node'], 'npm');
    expect(calls.length).toBe(1);
    expect(out.get('@types/node')).toBe(366424234);
  });

  it('mixes bulk + scoped, and a bulk null row (unknown package) yields no entry', async () => {
    stub((url) => {
      const tail = decodeURIComponent(url.split('/').pop()!);
      if (tail === '@scope/x') return new Response(JSON.stringify({ downloads: 5 }), { status: 200 });
      return new Response(JSON.stringify({ lodash: { downloads: 155449695 }, 'no-such-pkg-xyz': null }), {
        status: 200,
      });
    });
    const out = await fetchDownloads(['lodash', 'no-such-pkg-xyz', '@scope/x'], 'npm');
    expect(out.get('lodash')).toBe(155449695);
    expect(out.get('@scope/x')).toBe(5);
    expect(out.has('no-such-pkg-xyz')).toBe(false);
  });

  it('degrades (announced) on HTTP failure without dropping the whole scan', async () => {
    stub(() => new Response('down', { status: 503 }));
    const sources: string[] = [];
    const out = await fetchDownloads(['lodash'], 'npm', (s) => sources.push(s));
    expect(out.size).toBe(0);
    expect(sources).toEqual(['npm downloads']);
  });
});

describe('fetchDownloads (PyPI)', () => {
  it('reads last_week from pypistats (lowercased name in the URL)', async () => {
    stub((url) => {
      expect(url).toContain('/api/packages/requests/recent');
      return new Response(JSON.stringify({ data: { last_week: 384780216 }, package: 'requests' }), {
        status: 200,
      });
    });
    const out = await fetchDownloads(['Requests'], 'PyPI');
    expect(out.get('Requests')).toBe(384780216);
  });

  it('treats a 404 as "not a package" (no entry, no degrade)', async () => {
    stub(() => new Response('not found', { status: 404 }));
    const sources: string[] = [];
    const out = await fetchDownloads(['definitely-not-real'], 'PyPI', (s) => sources.push(s));
    expect(out.size).toBe(0);
    expect(sources).toEqual([]);
  });
});
