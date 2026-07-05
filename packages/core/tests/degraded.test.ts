import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { analyzeFiles } from '../src/analyze';
import { setCacheEnabled } from '../src/cache';
import { fetchEpss } from '../src/epss';
import { fetchKev } from '../src/kev';
import { fetchRegistry } from '../src/registry';

// The point of this file: a transient upstream failure must NOT be cached (a cached blank silently
// weakens detection for 24h), and it must be announced via the onDegraded callback / Report.degraded.

afterEach(() => {
  vi.unstubAllGlobals();
  setCacheEnabled(true);
});

describe('fetchKev — failure handling (#1)', () => {
  beforeEach(() => setCacheEnabled(false));

  it('degrades to empty + reports the source on a 500', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 500 })));
    const sources: string[] = [];
    const kev = await fetchKev((s) => sources.push(s));
    expect(kev.size).toBe(0);
    expect(sources).toEqual(['CISA KEV']);
  });

  it('treats an empty catalog (200 but no entries) as a failure, not "no KEVs"', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ vulnerabilities: [] }), { status: 200 })));
    const sources: string[] = [];
    expect((await fetchKev((s) => sources.push(s))).size).toBe(0);
    expect(sources).toEqual(['CISA KEV']);
  });

  it('does NOT cache a failure — the next call retries and can succeed', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'preflight-cache-test-'));
    const prev = process.env.PREFLIGHT_CACHE_DIR;
    process.env.PREFLIGHT_CACHE_DIR = dir;
    setCacheEnabled(true);
    try {
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(new Response('down', { status: 503 }))
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-1' }] }), { status: 200 }),
        );
      vi.stubGlobal('fetch', fetchMock);

      const first = await fetchKev(); // 503 → empty, must not be cached
      expect(first.size).toBe(0);
      const second = await fetchKev(); // retries the network (cache wasn't poisoned) → real data
      expect(second.has('CVE-1')).toBe(true);
      expect(fetchMock).toHaveBeenCalledTimes(2); // proof the failure wasn't served from cache
    } finally {
      if (prev === undefined) delete process.env.PREFLIGHT_CACHE_DIR;
      else process.env.PREFLIGHT_CACHE_DIR = prev;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('fetchRegistry — 404 is legit, other failures degrade (#1)', () => {
  beforeEach(() => setCacheEnabled(false));

  it('a 404 is a legitimate "no such package" — empty, NOT degraded', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('not found', { status: 404 })));
    const sources: string[] = [];
    const info = await fetchRegistry('does-not-exist', 'npm', (s) => sources.push(s));
    expect(info).toEqual({});
    expect(sources).toEqual([]); // 404 is not a degradation
  });

  it('a 500 degrades + reports the source', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('boom', { status: 500 })));
    const sources: string[] = [];
    await fetchRegistry('left-pad', 'npm', (s) => sources.push(s));
    expect(sources).toEqual(['npm registry']);
  });
});

describe('fetchEpss — a failed chunk degrades but does not sink the rest (#1)', () => {
  beforeEach(() => setCacheEnabled(false));

  it('reports FIRST EPSS on a 500 and returns an empty map for that chunk', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 500 })));
    const sources: string[] = [];
    const map = await fetchEpss(['CVE-1', 'CVE-2'], (s) => sources.push(s));
    expect(map.size).toBe(0);
    expect(sources).toEqual(['FIRST EPSS']);
  });
});

describe('analyzeFiles — Report.degraded surfaces the outage end-to-end (#1)', () => {
  beforeEach(() => setCacheEnabled(false));

  it('marks the scan degraded when KEV is unreachable but a CVE was found', async () => {
    // querybatch finds a vuln; the detail carries a CVE alias so enrichment runs; KEV 500s.
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: { body?: string }) => {
        if (url.endsWith('/v1/querybatch')) {
          const { queries } = JSON.parse(init!.body!) as { queries: { package: { name: string } }[] };
          return new Response(
            JSON.stringify({ results: queries.map((q) => (q.package.name === 'evil' ? { vulns: [{ id: 'GHSA-1' }] } : {})) }),
            { status: 200 },
          );
        }
        if (url.includes('/v1/vulns/GHSA-1')) {
          return new Response(
            JSON.stringify({ id: 'GHSA-1', summary: 'bug', aliases: ['CVE-2099-1'], database_specific: { severity: 'HIGH' } }),
            { status: 200 },
          );
        }
        if (url.includes('api.first.org')) return new Response(JSON.stringify({ data: [] }), { status: 200 });
        if (url.includes('cisa.gov')) return new Response('down', { status: 500 }); // KEV outage
        return new Response(JSON.stringify({ results: [] }), { status: 200 });
      }),
    );
    const report = await analyzeFiles({
      'package.json': JSON.stringify({ dependencies: { evil: '1.0.0' } }),
    });
    expect(report.degraded).toContain('CISA KEV');
    // the CVE is still reported — degradation announces the gap, it doesn't hide findings
    expect(report.findings.find((f) => f.name === 'evil')?.verdict).toBe('cve');
  });

  it('a fully successful scan has no degraded field', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ results: [] }), { status: 200 })));
    const report = await analyzeFiles({ 'package.json': JSON.stringify({ dependencies: { ok: '1.0.0' } }) });
    expect(report.degraded).toBeUndefined();
  });
});
