import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setCacheEnabled } from '../src/cache';
import { fetchRegistry } from '../src/registry';

// Full npm doc (registry.ts fetches without the corgi Accept header) + legacy PyPI JSON.
const NPM_DOC = {
  name: 'request',
  'dist-tags': { latest: '2.88.2' },
  time: { modified: '2020-02-11T00:00:00.000Z' },
  license: 'Apache-2.0',
  versions: {
    '2.88.2': { version: '2.88.2', deprecated: 'request has been deprecated, see https://github.com/request/request/issues/3142' },
    '2.88.1': { version: '2.88.1', deprecated: '' }, // un-deprecated: empty string is NOT a signal
    '2.88.0': { version: '2.88.0', deprecated: true }, // odd old docs: bare true
    '2.87.0': { version: '2.87.0' }, // never deprecated
  },
};

const PYPI_DOC = {
  info: { name: 'demo', version: '2.0.0', classifiers: ['License :: OSI Approved :: MIT License'] },
  urls: [{ upload_time_iso_8601: '2024-01-01T00:00:00Z' }],
  releases: {
    '2.0.0': [{ upload_time_iso_8601: '2024-01-01T00:00:00Z', yanked: false }],
    '1.9.0': [
      // FULLY yanked release — every file
      { yanked: true, yanked_reason: 'broken sdist' },
      { yanked: true, yanked_reason: null },
    ],
    '1.8.0': [
      // Partial yank (one bad wheel) — the release itself is still live
      { yanked: true, yanked_reason: 'bad wheel' },
      { yanked: false },
    ],
    '0.0.1': [], // no files
  },
};

beforeEach(() => {
  setCacheEnabled(false);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      if (url.startsWith('https://registry.npmjs.org/')) {
        return new Response(JSON.stringify(NPM_DOC), { status: 200 });
      }
      if (url.startsWith('https://pypi.org/pypi/')) {
        return new Response(JSON.stringify(PYPI_DOC), { status: 200 });
      }
      return new Response('nope', { status: 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCacheEnabled(true);
});

describe('fetchRegistry (npm) deprecation', () => {
  it('captures per-version deprecation messages, ignoring empty strings', async () => {
    const info = await fetchRegistry('request', 'npm');
    expect(info.latest).toBe('2.88.2');
    expect(info.deprecated?.['2.88.2']).toMatch(/has been deprecated/);
    expect(info.deprecated).not.toHaveProperty('2.88.1'); // '' = un-deprecated
    expect(info.deprecated?.['2.88.0']).toMatch(/no message given/); // bare true
    expect(info.deprecated).not.toHaveProperty('2.87.0');
  });
});

describe('fetchRegistry (PyPI) yanked releases', () => {
  it('marks only fully-yanked releases as deprecated, carrying the yank reason', async () => {
    const info = await fetchRegistry('demo', 'PyPI');
    expect(info.deprecated?.['1.9.0']).toBe('yanked from PyPI: broken sdist');
    expect(info.deprecated).not.toHaveProperty('1.8.0'); // partial yank stays live
    expect(info.deprecated).not.toHaveProperty('2.0.0');
    expect(info.deprecated).not.toHaveProperty('0.0.1'); // empty ≠ yanked
  });
});

describe('fetchRegistry omits the map when nothing is deprecated', () => {
  it('keeps the cached entry small for the common case', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': {} } }),
            { status: 200 },
          ),
      ),
    );
    const info = await fetchRegistry('clean', 'npm');
    expect(info.deprecated).toBeUndefined();
  });
});
