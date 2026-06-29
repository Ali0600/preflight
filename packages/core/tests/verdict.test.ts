import { describe, expect, it } from 'vitest';

import type { Vuln } from '../src/types';
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
