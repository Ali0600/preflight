import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setCacheEnabled } from '../src/cache';
import { fetchKev } from '../src/kev';

beforeEach(() => {
  setCacheEnabled(false);
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      new Response(
        JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-1' }, { cveID: 'CVE-2' }] }),
        { status: 200 },
      ),
    ),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCacheEnabled(true);
});

describe('fetchKev', () => {
  it('returns the catalog CVE ids as a set', async () => {
    const kev = await fetchKev();
    expect(kev.has('CVE-1')).toBe(true);
    expect(kev.has('CVE-999')).toBe(false);
  });

  it('degrades to an empty set on a failed fetch', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 500 })));
    expect((await fetchKev()).size).toBe(0);
  });
});
