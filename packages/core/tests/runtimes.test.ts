import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setCacheEnabled } from '../src/cache';
import { fetchRuntimeMeta } from '../src/runtimes';

// Corgi-shaped npm doc (abbreviated registry format) + legacy PyPI JSON.
const NPM_DOC = {
  name: 'esbuild',
  'dist-tags': { latest: '0.24.0' },
  versions: {
    '0.17.0': { version: '0.17.0', engines: { node: '>=12' } },
    '0.24.0': { version: '0.24.0', engines: { node: '>=18' } },
    '0.9.5': { version: '0.9.5' }, // no engines declared
  },
};

const PYPI_DOC = {
  info: { name: 'uvicorn', version: '0.49.0' },
  releases: {
    '0.39.0': [
      { filename: 'uvicorn-0.39.0-py3-none-any.whl', requires_python: '>=3.9', yanked: false },
    ],
    '0.49.0': [
      // sdist first with null requires_python — the wheel's value must win
      { filename: 'uvicorn-0.49.0.tar.gz', requires_python: null, yanked: false },
      { filename: 'uvicorn-0.49.0-py3-none-any.whl', requires_python: '>=3.10', yanked: false },
    ],
    '0.38.0': [
      { filename: 'uvicorn-0.38.0-py3-none-any.whl', requires_python: '>=3.9', yanked: true },
    ],
    '0.0.1': [], // no files at all
  },
};

let requestedAccept: string | undefined;

beforeEach(() => {
  setCacheEnabled(false);
  requestedAccept = undefined;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith('https://registry.npmjs.org/')) {
        requestedAccept = (init?.headers as Record<string, string> | undefined)?.Accept;
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

describe('fetchRuntimeMeta (npm)', () => {
  it('extracts per-version engines.node (null when undeclared) and requests the corgi doc', async () => {
    const meta = await fetchRuntimeMeta('esbuild', 'npm');
    expect(meta.latest).toBe('0.24.0');
    expect(meta.constraints['0.17.0']).toBe('>=12');
    expect(meta.constraints['0.24.0']).toBe('>=18');
    expect(meta.constraints['0.9.5']).toBeNull();
    expect(requestedAccept).toBe('application/vnd.npm.install-v1+json');
  });
});

describe('fetchRuntimeMeta (PyPI)', () => {
  it('takes the first non-null requires_python per release and skips yanked/empty releases', async () => {
    const meta = await fetchRuntimeMeta('uvicorn', 'PyPI');
    expect(meta.latest).toBe('0.49.0');
    expect(meta.constraints['0.39.0']).toBe('>=3.9');
    expect(meta.constraints['0.49.0']).toBe('>=3.10'); // null sdist skipped, wheel wins
    expect(meta.constraints).not.toHaveProperty('0.38.0'); // fully yanked
    expect(meta.constraints).not.toHaveProperty('0.0.1'); // no installable files
  });
});

describe('degradation', () => {
  it('returns empty metadata on HTTP errors and network failures', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 500 })));
    expect((await fetchRuntimeMeta('x', 'npm')).constraints).toEqual({});
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('offline');
      }),
    );
    expect((await fetchRuntimeMeta('x', 'PyPI')).constraints).toEqual({});
  });
});
