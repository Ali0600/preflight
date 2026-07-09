import { describe, expect, it } from 'vitest';

import type { RuntimeCompat, RuntimeTarget, Vuln } from '../src/types';
import { decideVerdict } from '../src/verdict';

const med: Vuln[] = [{ id: 'GHSA-test', summary: 'test advisory', severity: 'medium' }];

describe('decideVerdict', () => {
  it('a CVE wins over everything else', () => {
    const r = decideVerdict({
      name: 'js-yaml',
      range: '^4',
      version: '4.1.1',
      dev: false,
      vulns: med,
      lockstep: { pinned: false },
    });
    expect(r.verdict).toBe('cve');
  });

  it('a pinned dep that also has a CVE points at the framework fix', () => {
    const r = decideVerdict({
      name: 'react-native',
      range: '0.85.3',
      version: '0.85.3',
      dev: false,
      vulns: med,
      lockstep: { pinned: true, framework: 'Expo', tool: 'npx expo install' },
    });
    expect(r.verdict).toBe('cve');
    expect(r.reason).toContain('Expo');
  });

  it('framework-pinned with no CVE -> pinned', () => {
    const r = decideVerdict({
      name: 'react-native',
      range: '0.85.3',
      version: '0.85.3',
      dev: false,
      vulns: [],
      lockstep: { pinned: true, framework: 'Expo', tool: 'npx expo install' },
    });
    expect(r.verdict).toBe('pinned');
    expect(r.reason).toContain('expo install');
  });

  it('independent + clean -> safe', () => {
    const r = decideVerdict({
      name: 'fastapi',
      range: '>=0.115',
      version: '0.115.0',
      dev: false,
      vulns: [],
      lockstep: { pinned: false },
    });
    expect(r.verdict).toBe('safe');
  });
});

const daysAgo = (n: number) => new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();

describe('decideVerdict — stale', () => {
  const base = {
    name: 'left-pad',
    range: '^1.0.0',
    version: '1.3.0',
    dev: false,
    vulns: [],
    lockstep: { pinned: false as const },
  };

  it('major(s) behind AND old last-publish -> stale', () => {
    const r = decideVerdict({ ...base, latest: '3.0.0', lastPublish: daysAgo(800) });
    expect(r.verdict).toBe('stale');
    expect(r.reason).toContain('3.0.0');
  });

  it('major behind but recently published -> safe', () => {
    const r = decideVerdict({ ...base, latest: '3.0.0', lastPublish: daysAgo(30) });
    expect(r.verdict).toBe('safe');
  });

  it('same major (only minor behind) -> safe even if old', () => {
    const r = decideVerdict({ ...base, version: '1.9.0', latest: '1.9.5', lastPublish: daysAgo(800) });
    expect(r.verdict).toBe('safe');
  });

  it('without --latest data (no latest/lastPublish) -> safe', () => {
    const r = decideVerdict(base);
    expect(r.verdict).toBe('safe');
  });

  it('a CVE still wins over stale', () => {
    const r = decideVerdict({ ...base, vulns: med, latest: '3.0.0', lastPublish: daysAgo(800) });
    expect(r.verdict).toBe('cve');
  });
});

const PY39: RuntimeTarget = {
  runtime: 'python',
  version: '3.9',
  source: '.python-version',
  explicit: false,
};

const badFloor: RuntimeCompat = {
  target: PY39,
  rangeUnsatisfiable: true,
  resolvedIncompatible: false,
  latestIncompatible: true,
  maxCompatible: '0.39.0',
  firstIncompatible: '0.40.0',
  constraint: '>=3.10',
};

describe('decideVerdict — runtime incompatibility', () => {
  const base = { name: 'uvicorn', range: '>=0.49', dev: false, vulns: [], lockstep: { pinned: false as const } };

  it('an unsatisfiable range -> incompatible, naming the boundary and the max compatible', () => {
    const r = decideVerdict({ ...base, runtimeCompat: badFloor });
    expect(r.verdict).toBe('incompatible');
    expect(r.reason).toContain('Python 3.9');
    expect(r.reason).toContain('(.python-version)');
    expect(r.reason).toContain('0.40.0+ requires Python >=3.10');
    expect(r.reason).toContain('max compatible 0.39.0');
  });

  it('a locked incompatible version -> incompatible', () => {
    const rc: RuntimeCompat = { ...badFloor, rangeUnsatisfiable: false, resolvedIncompatible: true };
    const r = decideVerdict({ ...base, version: '0.49.0', runtimeCompat: rc });
    expect(r.verdict).toBe('incompatible');
    expect(r.reason).toContain('Locked 0.49.0');
  });

  it('npm engines wording is advisory ("declares engines node"), pip is hard ("requires Python")', () => {
    const rc: RuntimeCompat = {
      target: { runtime: 'node', version: '18', source: '--node flag', explicit: true },
      rangeUnsatisfiable: true,
      resolvedIncompatible: false,
      latestIncompatible: true,
      maxCompatible: '2.0.0',
      firstIncompatible: '3.0.0',
      constraint: '>=20',
    };
    const r = decideVerdict({ ...base, name: 'pkg', range: '^3.0.0', runtimeCompat: rc });
    expect(r.reason).toContain('declares engines node >=20');
  });

  it('latestIncompatible alone does NOT change the verdict (warning-only)', () => {
    const rc: RuntimeCompat = { ...badFloor, rangeUnsatisfiable: false };
    expect(decideVerdict({ ...base, range: '>=0.30,<0.40', runtimeCompat: rc }).verdict).toBe('safe');
  });

  it('a CVE outranks incompatible; incompatible outranks pinned (with the lockstep tail)', () => {
    expect(decideVerdict({ ...base, vulns: med, runtimeCompat: badFloor }).verdict).toBe('cve');
    const r = decideVerdict({
      ...base,
      lockstep: { pinned: true, framework: 'Expo', tool: 'npx expo install' },
      runtimeCompat: badFloor,
    });
    expect(r.verdict).toBe('incompatible');
    expect(r.reason).toContain('framework-pinned (Expo)');
  });
});

describe('decideVerdict — exploitability + malware', () => {
  const base = { name: 'x', range: '^1', version: '1.0.0', dev: false, lockstep: { pinned: false as const } };

  it('a malicious package outranks everything (even a lockstep pin)', () => {
    const r = decideVerdict({
      ...base,
      vulns: [{ id: 'MAL-1', summary: 'm', severity: 'critical', malicious: true }],
      lockstep: { pinned: true, framework: 'Expo', tool: 'npx expo install' },
    });
    expect(r.verdict).toBe('malware');
  });

  it('a KEV-listed CVE reason flags it as actively exploited', () => {
    const r = decideVerdict({
      ...base,
      vulns: [{ id: 'CVE-1', summary: 'v', severity: 'high', cve: 'CVE-1', kev: true, epss: 0.5 }],
    });
    expect(r.verdict).toBe('cve');
    expect(r.reason).toContain('actively exploited (KEV)');
  });

  it('a high-EPSS CVE reason names the probability (KEV takes priority when both)', () => {
    const r = decideVerdict({
      ...base,
      vulns: [{ id: 'CVE-2', summary: 'v', severity: 'high', cve: 'CVE-2', epss: 0.87 }],
    });
    expect(r.reason).toContain('EPSS 0.87');
  });
});

describe('decideVerdict — precedence holds under combined signals (malware > cve > incompatible > pinned > stale)', () => {
  const base = { name: 'x', range: '^1', version: '1.0.0', dev: false, lockstep: { pinned: false as const } };
  // Qualifies as stale on its own: 2 majors behind, last published years ago.
  const staleBits = { latest: '3.0.0', lastPublish: '2020-01-01T00:00:00Z' };
  const brokenRuntime = {
    target: { runtime: 'node' as const, version: '18', source: '--node flag', explicit: true },
    rangeUnsatisfiable: true,
    resolvedIncompatible: false,
    latestIncompatible: true,
  };

  it('stale + CVE → cve (a stale dep with an advisory must never read as merely old)', () => {
    const r = decideVerdict({
      ...base,
      ...staleBits,
      vulns: [{ id: 'GHSA-1', summary: 's', severity: 'medium' }],
    });
    expect(r.verdict).toBe('cve');
  });

  it('stale + malware → malware', () => {
    const r = decideVerdict({
      ...base,
      ...staleBits,
      vulns: [{ id: 'MAL-2', summary: 'm', severity: 'critical', malicious: true }],
    });
    expect(r.verdict).toBe('malware');
  });

  it('stale + incompatible → incompatible (broken beats old)', () => {
    const r = decideVerdict({ ...base, ...staleBits, vulns: [], runtimeCompat: brokenRuntime });
    expect(r.verdict).toBe('incompatible');
  });

  it('stale + pinned → pinned (the framework owns the upgrade path)', () => {
    const r = decideVerdict({
      ...base,
      ...staleBits,
      vulns: [],
      lockstep: { pinned: true, framework: 'Expo', tool: 'npx expo install' },
    });
    expect(r.verdict).toBe('pinned');
  });

  it('incompatible + CVE → cve (the advisory still outranks installability)', () => {
    const r = decideVerdict({
      ...base,
      vulns: [{ id: 'GHSA-2', summary: 's', severity: 'high' }],
      runtimeCompat: brokenRuntime,
    });
    expect(r.verdict).toBe('cve');
  });
});

describe('decideVerdict — deprecated', () => {
  const dep = {
    name: 'request',
    range: '^2.88',
    version: '2.88.2',
    dev: false,
    vulns: [] as Vuln[],
    lockstep: { pinned: false },
    deprecated: 'request has been deprecated',
  };

  it('a deprecated dep with nothing worse -> deprecated, reason carries the upstream message', () => {
    const r = decideVerdict(dep);
    expect(r.verdict).toBe('deprecated');
    expect(r.reason).toContain('request has been deprecated');
  });

  it('deprecated + CVE -> cve (the vulnerability outranks the notice)', () => {
    const r = decideVerdict({ ...dep, vulns: med });
    expect(r.verdict).toBe('cve');
  });

  it('deprecated + framework-pinned -> deprecated, with the framework fix in the tail', () => {
    const r = decideVerdict({
      ...dep,
      lockstep: { pinned: true, framework: 'Expo', tool: 'npx expo install' },
    });
    expect(r.verdict).toBe('deprecated');
    expect(r.reason).toContain('npx expo install');
  });

  it('truncates a very long deprecation message', () => {
    const r = decideVerdict({ ...dep, deprecated: 'x'.repeat(500) });
    expect(r.reason.length).toBeLessThan(200);
    expect(r.reason).toContain('…');
  });
});
