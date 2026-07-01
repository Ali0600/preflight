import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setCacheEnabled } from '../src/cache';
import { fetchVulns } from '../src/osv';
import type { Dependency } from '../src/types';

// OSV details by id: a GHSA record (w/ CVE alias), a CVSS-vector-only record, a malicious package.
const VULNS: Record<string, unknown> = {
  'GHSA-yaml': {
    id: 'GHSA-yaml',
    summary: 'yaml bug',
    aliases: ['CVE-2099-0001'],
    database_specific: { severity: 'HIGH' },
  },
  'CVE-foo': {
    id: 'CVE-foo',
    summary: 'foo bug',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  },
  'MAL-evil': { id: 'MAL-evil', summary: 'malicious package' },
  'GHSA-chunk': { id: 'GHSA-chunk', summary: 'chunk boundary', database_specific: { severity: 'HIGH' } },
};

beforeEach(() => {
  setCacheEnabled(false); // hit the (mocked) network, not a previous run's disk cache
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: { body?: string }) => {
      if (url.endsWith('/v1/querybatch')) {
        const { queries } = JSON.parse(init!.body!) as { queries: { package: { name: string } }[] };
        const results = queries.map((q) => {
          if (q.package.name === 'js-yaml') return { vulns: [{ id: 'GHSA-yaml' }] };
          if (q.package.name === 'foo') return { vulns: [{ id: 'CVE-foo' }] };
          if (q.package.name === 'evil') return { vulns: [{ id: 'MAL-evil' }] };
          if (q.package.name.startsWith('vuln-')) return { vulns: [{ id: 'GHSA-chunk' }] };
          return {};
        });
        return new Response(JSON.stringify({ results }), { status: 200 });
      }
      const id = url.split('/v1/vulns/')[1];
      return id && VULNS[id]
        ? new Response(JSON.stringify(VULNS[id]), { status: 200 })
        : new Response('not found', { status: 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCacheEnabled(true);
});

describe('fetchVulns', () => {
  const deps: Dependency[] = [
    { name: 'js-yaml', range: '^4', version: '4.1.0', dev: false },
    { name: 'foo', range: '^1', version: '1.0.0', dev: false },
    { name: 'evil', range: '1.0.0', version: '1.0.0', dev: false },
    { name: 'clean', range: '^2', version: '2.0.0', dev: false },
    { name: 'no-version', range: '^1', dev: false }, // unresolved → never queried
  ];

  it('maps GHSA labels and falls back to the CVSS vector (keyed by name@version)', async () => {
    const map = await fetchVulns(deps, 'npm');
    expect(map.get('js-yaml@4.1.0')?.[0].severity).toBe('high');
    expect(map.get('js-yaml@4.1.0')?.[0].cve).toBe('CVE-2099-0001'); // captured from aliases
    expect(map.get('foo@1.0.0')?.[0].severity).toBe('critical'); // derived from the CVSS vector
  });

  it('classifies MAL- advisories as malicious + critical', async () => {
    const map = await fetchVulns(deps, 'npm');
    expect(map.get('evil@1.0.0')?.[0]).toMatchObject({ malicious: true, severity: 'critical' });
  });

  it('omits clean deps and never queries unresolved ones', async () => {
    const map = await fetchVulns(deps, 'npm');
    expect(map.has('clean@2.0.0')).toBe(false);
    expect([...map.keys()].some((k) => k.startsWith('no-version'))).toBe(false);
    const body = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0][1].body as string;
    expect(body).not.toContain('no-version'); // filtered before the batch query
  });

  it('splits >1000 queries into chunks and keeps results aligned by name@version', async () => {
    // 1001 unique deps → two querybatch calls; a vuln sits in each chunk (index 0 and index 1000).
    const many: Dependency[] = [
      { name: 'vuln-early', range: '1.0.0', version: '1.0.0', dev: false },
      ...Array.from({ length: 999 }, (_, i) => ({
        name: `filler-${i}`,
        range: '1.0.0',
        version: '1.0.0',
        dev: false,
      })),
      { name: 'vuln-late', range: '1.0.0', version: '1.0.0', dev: false },
    ];
    expect(many).toHaveLength(1001);

    const map = await fetchVulns(many, 'npm');
    expect(map.get('vuln-early@1.0.0')?.[0].id).toBe('GHSA-chunk'); // first chunk
    expect(map.get('vuln-late@1.0.0')?.[0].id).toBe('GHSA-chunk'); // second chunk

    const batchCalls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.filter((c) =>
      (c[0] as string).endsWith('/v1/querybatch'),
    );
    expect(batchCalls).toHaveLength(2);
  });
});
