import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setCacheEnabled } from '../src/cache';
import { fetchHealth } from '../src/depsdev';

beforeEach(() => {
  setCacheEnabled(false);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      if (url.includes('/versions/')) {
        return new Response(
          JSON.stringify({
            relatedProjects: [
              { projectKey: { id: 'github.com/x/y' }, relationType: 'SOURCE_REPO' },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes('/projects/')) {
        return new Response(
          JSON.stringify({
            scorecard: {
              overallScore: 6.2,
              checks: [
                { name: 'Dangerous-Workflow', score: 10 },
                { name: 'Branch-Protection', score: 2 },
                { name: 'Code-Review', score: -1 }, // not run → dropped
                { name: 'CII-Best-Practices', score: 1 }, // not in curated set → dropped
              ],
            },
          }),
          { status: 200 },
        );
      }
      return new Response('nope', { status: 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCacheEnabled(true);
});

describe('fetchHealth', () => {
  it('returns the overall score + security-relevant checks, dropping not-run and off-list checks', async () => {
    const h = await fetchHealth('pkg', '1.0.0', 'npm');
    expect(h.score).toBe(6.2);
    expect((h.checks ?? []).map((c) => c.name).sort()).toEqual([
      'Branch-Protection',
      'Dangerous-Workflow',
    ]);
  });
});

describe('fetchHealth — provenance + license (same GetVersion call)', () => {
  it('summarizes verified attestations and detected SPDX licenses', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('/versions/')) {
          return new Response(
            JSON.stringify({
              licenses: ['Apache-2.0'],
              // Shape verified live: sigstore@5.0.0 (npm) / pypi-attestations (PEP 740)
              slsaProvenances: [
                { sourceRepository: 'https://github.com/sigstore/sigstore-js', verified: true },
              ],
              attestations: [
                { type: 'https://slsa.dev/provenance/v1', verified: true, sourceRepository: 'https://github.com/sigstore/sigstore-js' },
              ],
              relatedProjects: [],
            }),
            { status: 200 },
          );
        }
        return new Response('nope', { status: 404 });
      }),
    );
    const h = await fetchHealth('sigstore', '5.0.0', 'npm');
    expect(h.provenance).toEqual({
      verified: true,
      sourceRepository: 'https://github.com/sigstore/sigstore-js',
    });
    expect(h.license).toBe('Apache-2.0');
    expect(h.score).toBeUndefined(); // no linked project — provenance/license still returned
  });

  it('reports an unverified attestation as present but not verified', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('/versions/')) {
          return new Response(
            JSON.stringify({ attestations: [{ verified: false }], relatedProjects: [] }),
            { status: 200 },
          );
        }
        return new Response('nope', { status: 404 });
      }),
    );
    const h = await fetchHealth('pkg', '1.0.0', 'npm');
    expect(h.provenance?.verified).toBe(false);
  });

  it('returns no provenance when the version ships none (empty arrays)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('/versions/')) {
          return new Response(
            JSON.stringify({ slsaProvenances: [], attestations: [], relatedProjects: [] }),
            { status: 200 },
          );
        }
        return new Response('nope', { status: 404 });
      }),
    );
    expect((await fetchHealth('left-pad', '1.3.0', 'npm')).provenance).toBeUndefined();
  });
});
