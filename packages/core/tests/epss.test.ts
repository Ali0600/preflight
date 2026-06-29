import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setCacheEnabled } from '../src/cache';
import { fetchEpss } from '../src/epss';

beforeEach(() => {
  setCacheEnabled(false);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      const cves = new URL(url).searchParams.get('cve')?.split(',') ?? [];
      const data = cves
        .filter((c) => c === 'CVE-1' || c === 'CVE-2')
        .map((cve) => ({
          cve,
          epss: cve === 'CVE-1' ? '0.97000' : '0.01200',
          percentile: cve === 'CVE-1' ? '0.99900' : '0.40000',
        }));
      return new Response(JSON.stringify({ data }), { status: 200 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCacheEnabled(true);
});

describe('fetchEpss', () => {
  it('parses string scores into numbers and ignores non-CVE / unknown ids', async () => {
    const map = await fetchEpss(['CVE-1', 'CVE-2', 'GHSA-x', 'CVE-unknown']);
    expect(map.get('CVE-1')).toEqual({ epss: 0.97, percentile: 0.999 });
    expect(map.get('CVE-2')?.epss).toBeCloseTo(0.012);
    expect(map.has('CVE-unknown')).toBe(false);
    const body = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(body).not.toContain('GHSA-x'); // GHSA ids filtered before the request
  });
});
