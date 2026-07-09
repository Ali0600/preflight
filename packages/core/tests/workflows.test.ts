import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setCacheEnabled } from '../src/cache';
import { parseManifestContent } from '../src/manifest';
import { fetchVulns } from '../src/osv';
import { evaluatePolicy } from '../src/policy';
import type { Finding } from '../src/types';

const WORKFLOW = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8edcb1bdb4e267140fa742c62e395cd74f332709
      - uses: actions/setup-node@v4
      - uses: tj-actions/changed-files@45.0.7
      - uses: github/codeql-action/upload-sarif@v3.28.0
      - uses: ./local-action
      - uses: docker://alpine:3.20
      - run: npm test
  release:
    uses: my-org/workflows/.github/workflows/release.yml@main
`;

describe('parseManifestContent (.github/workflows)', () => {
  it('extracts uses: entries with SHA/tag classification, skipping local and docker uses', () => {
    const m = parseManifestContent('.github/workflows/ci.yml', WORKFLOW);
    expect(m.ecosystem).toBe('actions');
    const byName = Object.fromEntries(m.dependencies.map((d) => [`${d.name}@${d.range}`, d]));

    const checkout = byName['actions/checkout@8edcb1bdb4e267140fa742c62e395cd74f332709']!;
    expect(checkout.mutableRef).toBe(false); // full SHA = immutable
    expect(checkout.version).toBeUndefined();

    const node = byName['actions/setup-node@v4']!;
    expect(node.mutableRef).toBe(true); // bare major tag floats
    expect(node.version).toBeUndefined();

    const tj = byName['tj-actions/changed-files@45.0.7']!;
    expect(tj.mutableRef).toBe(true);
    expect(tj.version).toBe('45.0.7'); // exact release — advisory-matchable

    // Subpath action resolves to the repo; reusable workflow call is captured too.
    expect(byName['github/codeql-action@v3.28.0']!.version).toBe('3.28.0');
    expect(byName['my-org/workflows@main']!.mutableRef).toBe(true);

    expect(m.dependencies.some((d) => d.name.startsWith('./'))).toBe(false);
    expect(m.dependencies).toHaveLength(5);
  });

  it('rejects a .yml that is not under .github/workflows', () => {
    expect(() => parseManifestContent('docker-compose.yml', 'services: {}')).toThrow(/Unsupported/);
  });
});

// OSV shape as verified live 2026-07-09: version queries return {} for GitHub Actions, so the
// client queries per package and matches ECOSYSTEM ranges locally.
const TJ_ADVISORIES = {
  vulns: [
    {
      id: 'GHSA-mrrh-fwg8-r2c3',
      summary: 'tj-actions changed-files allows remote attackers to discover secrets',
      database_specific: { severity: 'HIGH' },
      affected: [
        {
          package: { name: 'tj-actions/changed-files', ecosystem: 'GitHub Actions' },
          ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '46.0.1' }] }],
        },
      ],
    },
    {
      id: 'GHSA-mcph-m25j-8j63',
      summary: 'command injection',
      database_specific: { severity: 'HIGH' },
      affected: [
        {
          package: { name: 'tj-actions/changed-files', ecosystem: 'GitHub Actions' },
          ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '41' }] }],
        },
      ],
    },
  ],
};

describe('fetchVulns (actions) — local range matching', () => {
  beforeEach(() => setCacheEnabled(false));
  afterEach(() => {
    vi.unstubAllGlobals();
    setCacheEnabled(true);
  });

  it('matches ECOSYSTEM ranges locally against the used version', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(TJ_ADVISORIES), { status: 200 })));
    const out = await fetchVulns(
      [{ name: 'tj-actions/changed-files', range: '45.0.7', version: '45.0.7', dev: false, direct: true }],
      'actions',
    );
    const vulns = out.get('tj-actions/changed-files@45.0.7') ?? [];
    // 45.0.7 is in [0, 46.0.1) but NOT in [0, 41) — partial boundary "41" padded to 41.0.0.
    expect(vulns.map((v) => v.id)).toEqual(['GHSA-mrrh-fwg8-r2c3']);
    expect(vulns[0]!.severity).toBe('high');
  });

  it('does not attach range-scoped advisories to a floating tag or SHA ref', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(TJ_ADVISORIES), { status: 200 })));
    const out = await fetchVulns(
      [{ name: 'tj-actions/changed-files', range: 'v45', version: undefined, dev: false, direct: true }],
      'actions',
    );
    expect(out.size).toBe(0);
  });

  it('attaches an unscoped advisory (no ranges, no versions) to every ref — fail-safe', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              vulns: [
                {
                  id: 'MAL-2025-0001',
                  summary: 'compromised action',
                  affected: [{ package: { name: 'evil/action', ecosystem: 'GitHub Actions' } }],
                },
              ],
            }),
            { status: 200 },
          ),
      ),
    );
    const out = await fetchVulns(
      [{ name: 'evil/action', range: 'v1', version: undefined, dev: false, direct: true }],
      'actions',
    );
    const vulns = out.get('evil/action@undefined') ?? [];
    expect(vulns[0]!.malicious).toBe(true);
    expect(vulns[0]!.severity).toBe('critical');
  });

  it('degrades (announced) when the OSV query fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('down', { status: 503 })));
    const sources: string[] = [];
    const out = await fetchVulns(
      [{ name: 'actions/checkout', range: 'v4', version: undefined, dev: false, direct: true }],
      'actions',
      (s) => sources.push(s),
    );
    expect(out.size).toBe(0);
    expect(sources).toEqual(['OSV advisory details']);
  });
});

describe('evaluatePolicy — unpinned-action rule', () => {
  const finding = (over: Partial<Finding>): Finding => ({
    name: 'actions/setup-node',
    range: 'v4',
    dev: false,
    vulns: [],
    lockstep: { pinned: false },
    verdict: 'safe',
    reason: 'ok',
    ...over,
  });

  it('fails a mutable ref only when the rule is on', () => {
    const f = finding({ mutableRef: true });
    expect(evaluatePolicy([f], { failOn: {} }).fail).toBe(false);
    const on = evaluatePolicy([f], { failOn: { unpinnedAction: true } });
    expect(on.fail).toBe(true);
    expect(on.violations[0]).toMatchObject({ rule: 'unpinned-action' });
    expect(evaluatePolicy([finding({ mutableRef: false })], { failOn: { unpinnedAction: true } }).fail).toBe(false);
  });
});

describe('actions report ledger', () => {
  beforeEach(() => setCacheEnabled(false));
  afterEach(() => {
    vi.unstubAllGlobals();
    setCacheEnabled(true);
  });

  it('uses a distinct OSV row name so run-level aggregation cannot clobber package rows', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ vulns: [] }), { status: 200 })));
    const { analyzeManifest } = await import('../src/analyze');
    const report = await analyzeManifest({
      ecosystem: 'actions',
      path: '.github/workflows/ci.yml',
      dependencies: [
        { name: 'actions/checkout', range: 'abc123'.padEnd(40, '0'), dev: false, direct: true, mutableRef: false },
        { name: 'actions/setup-node', range: 'v4', dev: false, direct: true, mutableRef: true },
      ],
    });
    const names = (report.sources ?? []).map((s) => s.name);
    expect(names).toContain('OSV.dev (GitHub Actions advisories)');
    expect(names).not.toContain('OSV.dev (advisories)'); // the package-row name stays free
    const pinRow = report.sources!.find((s) => s.name === 'ref pinning (offline)')!;
    expect(pinRow.detail).toContain('1 of 2');
    // No registry-style rows for a workflow manifest.
    expect(names.some((n) => n.includes('npm registry') || n.includes('deps.dev'))).toBe(false);
  });
});
