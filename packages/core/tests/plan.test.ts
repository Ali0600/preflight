import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setCacheEnabled } from '../src/cache';
import { buildPlan, frameworkSet } from '../src/plan';
import type { RuntimeTarget } from '../src/types';

const PY39: RuntimeTarget = { runtime: 'python', version: '3.9', source: '--python flag', explicit: true };
const NODE18: RuntimeTarget = { runtime: 'node', version: '18', source: '--node flag', explicit: true };

// Per-package release histories shaped like the 2026-07-02 incident.
const PYPI: Record<string, unknown> = {
  uvicorn: {
    info: { version: '0.49.0' },
    releases: {
      '0.39.0': [{ filename: 'u.whl', requires_python: '>=3.9', yanked: false }],
      '0.40.0': [{ filename: 'u.whl', requires_python: '>=3.10', yanked: false }],
      '0.49.0': [{ filename: 'u.whl', requires_python: '>=3.10', yanked: false }],
    },
  },
  httpx: {
    info: { version: '0.28.1' },
    releases: {
      '0.27.0': [{ filename: 'h.whl', requires_python: '>=3.8', yanked: false }],
      '0.28.1': [{ filename: 'h.whl', requires_python: '>=3.8', yanked: false }],
    },
  },
  pytest: {
    info: { version: '9.1.1' },
    releases: {
      '8.4.1': [{ filename: 'p.whl', requires_python: '>=3.9', yanked: false }],
      '9.0.0': [{ filename: 'p.whl', requires_python: '>=3.10', yanked: false }],
      '9.1.1': [{ filename: 'p.whl', requires_python: '>=3.10', yanked: false }],
    },
  },
};

const NPM: Record<string, unknown> = {
  axios: {
    'dist-tags': { latest: '2.0.0' },
    versions: {
      '1.7.0': { engines: { node: '>=14' } },
      '2.0.0': { engines: { node: '>=20' } },
    },
  },
  expo: {
    'dist-tags': { latest: '56.0.0' },
    versions: { '56.0.0': { engines: { node: '>=18' } } },
  },
};

beforeEach(() => {
  setCacheEnabled(false);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: { body?: string }) => {
      if (url.endsWith('/v1/querybatch')) {
        const { queries } = JSON.parse(init!.body!) as { queries: { package: { name: string } }[] };
        const results = queries.map((q) =>
          q.package.name === 'httpx' ? { vulns: [{ id: 'GHSA-h' }] } : {},
        );
        return new Response(JSON.stringify({ results }), { status: 200 });
      }
      if (url.includes('/v1/vulns/GHSA-h')) {
        return new Response(
          JSON.stringify({ id: 'GHSA-h', summary: 'h bug', database_specific: { severity: 'HIGH' } }),
          { status: 200 },
        );
      }
      const pypi = url.match(/pypi\.org\/pypi\/([^/]+)\/json/);
      if (pypi && PYPI[pypi[1]]) return new Response(JSON.stringify(PYPI[pypi[1]]), { status: 200 });
      const npm = url.match(/registry\.npmjs\.org\/(.+)$/);
      if (npm && NPM[decodeURIComponent(npm[1])]) {
        return new Response(JSON.stringify(NPM[decodeURIComponent(npm[1])]), { status: 200 });
      }
      return new Response('nope', { status: 404 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCacheEnabled(true);
});

describe('buildPlan (pip, the incident round-trip)', () => {
  it('caps floors at the runtime boundary and generates matching artifacts', async () => {
    const plan = await buildPlan({
      ecosystem: 'PyPI',
      packages: ['uvicorn', 'httpx'],
      dev: ['pytest'],
      target: PY39,
    });
    const by = Object.fromEntries(plan.packages.map((p) => [p.name, p]));

    expect(by.uvicorn).toMatchObject({
      recommended: '0.39.0',
      floor: '>=0.39.0,<0.40',
      capped: true,
      firstIncompatible: '0.40.0',
      constraint: '>=3.10',
    });
    expect(by.httpx).toMatchObject({ recommended: '0.28.1', floor: '>=0.28.1', capped: false });
    expect(by.pytest).toMatchObject({ recommended: '8.4.1', floor: '>=8.4.1,<9', dev: true });

    expect(plan.artifacts.manifest.filename).toBe('requirements.txt');
    expect(plan.artifacts.manifest.content).toContain('uvicorn>=0.39.0,<0.40');
    expect(plan.artifacts.manifest.content).toContain('# dev · 9.0.0+ requires Python >=3.10');
    expect(plan.artifacts.dependabot.content).toContain('- dependency-name: uvicorn');
    expect(plan.artifacts.dependabot.content).toContain("versions: ['>=0.40']");
    expect(plan.artifacts.dependabot.content).toContain("versions: ['>=9']");
    // httpx never dropped 3.9 — no ignore rule for it
    expect(plan.artifacts.dependabot.content).not.toContain('dependency-name: httpx');
  });

  it('surfaces a known advisory against a recommended version (not auto-stepped)', async () => {
    const plan = await buildPlan({ ecosystem: 'PyPI', packages: ['httpx'], target: PY39 });
    expect(plan.packages[0].vulns).toHaveLength(1);
    expect(plan.packages[0].note).toContain('1 known advisory against 0.28.1');
  });

  it('notes packages with no registry metadata instead of failing', async () => {
    const plan = await buildPlan({ ecosystem: 'PyPI', packages: ['no-such-pkg'], target: PY39 });
    expect(plan.packages[0].floor).toBeUndefined();
    expect(plan.packages[0].note).toContain('no registry metadata');
  });
});

describe('buildPlan (npm + framework)', () => {
  it('seeds the lockstep set, ignores it in dependabot, and caps independents by engines', async () => {
    const plan = await buildPlan({
      ecosystem: 'npm',
      packages: ['axios'],
      framework: 'expo',
      target: NODE18,
    });
    const names = plan.packages.map((p) => p.name);
    expect(names).toContain('expo');
    expect(names).toContain('react-native');
    const axios = plan.packages.find((p) => p.name === 'axios')!;
    expect(axios).toMatchObject({ recommended: '1.7.0', capped: true, firstIncompatible: '2.0.0' });
    expect(axios.floor).toBe('^1.7.0'); // boundary is the next major — caret already stops there

    expect(plan.lockstepAdvice?.framework).toBe('Expo');
    const yml = plan.artifacts.dependabot.content;
    expect(yml).toContain('- dependency-name: expo');
    expect(yml).toContain("- dependency-name: 'expo-*'");
    expect(yml).toContain("- dependency-name: '@expo/*'");
    expect(yml).toContain('npx expo install');
    // axios dropped node 18 at 2.0.0 → boundary ignore
    expect(yml).toContain('- dependency-name: axios');
    expect(yml).toContain("versions: ['>=2']");

    expect(plan.artifacts.manifest.filename).toBe('package.json');
    const json = JSON.parse(plan.artifacts.manifest.content) as {
      engines: { node: string };
      dependencies: Record<string, string>;
    };
    expect(json.engines.node).toBe('>=18');
    expect(json.dependencies.axios).toBe('^1.7.0');
  });

  it('rejects an unknown framework with the known list', async () => {
    await expect(
      buildPlan({ ecosystem: 'npm', packages: [], framework: 'django', target: NODE18 }),
    ).rejects.toThrow(/Unknown framework "django"/);
  });

  it('frameworkSet is case-insensitive', () => {
    expect(frameworkSet('EXPO')?.framework).toBe('Expo');
    expect(frameworkSet('next.js')?.framework).toBe('Next.js');
    expect(frameworkSet('rails')).toBeUndefined();
  });
});
