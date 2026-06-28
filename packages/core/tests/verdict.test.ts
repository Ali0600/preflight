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
