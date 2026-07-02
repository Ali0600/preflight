import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { evaluatePolicy, loadPolicy, meetsVulnLevel, policyNeeds, type Policy } from '../src/policy';
import type { Finding } from '../src/types';

function finding(over: Partial<Finding> & { name: string }): Finding {
  return {
    range: '^1',
    version: '1.0.0',
    dev: false,
    vulns: [],
    lockstep: { pinned: false },
    verdict: 'safe',
    reason: 'ok',
    ...over,
  };
}

describe('meetsVulnLevel', () => {
  const cve = (v: Partial<Finding['vulns'][number]>) =>
    finding({ name: 'x', verdict: 'cve', vulns: [{ id: 'CVE-x', summary: 's', severity: 'high', cve: 'CVE-x', ...v }] });

  it('malware always meets the bar; cve matches any; kev/epss are stricter', () => {
    expect(meetsVulnLevel(finding({ name: 'm', verdict: 'malware' }), 'kev')).toBe(true);
    expect(meetsVulnLevel(cve({}), 'cve')).toBe(true);
    expect(meetsVulnLevel(cve({}), 'kev')).toBe(false);
    expect(meetsVulnLevel(cve({ kev: true }), 'kev')).toBe(true);
    expect(meetsVulnLevel(cve({ epss: 0.8 }), 'epss:0.5')).toBe(true);
    expect(meetsVulnLevel(cve({ epss: 0.2 }), 'epss:0.5')).toBe(false);
  });
});

describe('evaluatePolicy', () => {
  it('flags each enabled rule and nothing more', () => {
    const findings = [
      finding({ name: 'scripted', installScript: true }),
      finding({ name: 'lodahs', suspiciousName: { similarTo: 'lodash' } }),
      finding({ name: 'gpl-dep', license: 'GPL-3.0' }),
      finding({ name: 'weak', direct: true, health: 3 }),
      finding({ name: 'clean' }),
    ];
    const policy: Policy = {
      failOn: {
        installScript: true,
        suspiciousName: true,
        license: ['copyleft'],
        minHealth: 5,
      },
    };
    const { violations, fail } = evaluatePolicy(findings, policy);
    expect(fail).toBe(true);
    expect(violations.map((v) => v.rule).sort()).toEqual([
      'install-script',
      'license',
      'min-health',
      'suspicious-name',
    ]);
  });

  it('matches a specific denied license id, and the copyleft bucket', () => {
    const mit = finding({ name: 'a', license: 'MIT' });
    const gpl = finding({ name: 'b', license: 'GPL-3.0' });
    expect(evaluatePolicy([mit, gpl], { failOn: { license: ['MIT'] } }).violations).toHaveLength(1);
    expect(evaluatePolicy([mit, gpl], { failOn: { license: ['copyleft'] } }).violations).toHaveLength(1);
  });

  it('passes cleanly when no rule trips', () => {
    const r = evaluatePolicy([finding({ name: 'clean' })], { failOn: { installScript: true } });
    expect(r.fail).toBe(false);
    expect(r.violations).toHaveLength(0);
  });
});

describe('evaluatePolicy — runtime rule', () => {
  const rc = {
    target: { runtime: 'python' as const, version: '3.9', source: '--python flag', explicit: true },
    rangeUnsatisfiable: false,
    resolvedIncompatible: false,
    latestIncompatible: true,
    maxCompatible: '0.39.0',
    firstIncompatible: '0.40.0',
    constraint: '>=3.10',
  };

  it("'incompatible' fails on broken range/lock, not on latest-dropped alone", () => {
    const broken = finding({
      name: 'uvicorn',
      verdict: 'incompatible',
      reason: 'No version installs',
      runtimeCompat: { ...rc, rangeUnsatisfiable: true },
    });
    const warned = finding({ name: 'fastapi', runtimeCompat: rc });
    const policy: Policy = { failOn: { runtime: 'incompatible' } };
    const r = evaluatePolicy([broken, warned], policy);
    expect(r.fail).toBe(true);
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0]).toMatchObject({ rule: 'runtime', dep: 'uvicorn@1.0.0' });
  });

  it("'latest-dropped' also fails the early warning, naming the ignore boundary", () => {
    const warned = finding({ name: 'fastapi', runtimeCompat: rc });
    const r = evaluatePolicy([warned], { failOn: { runtime: 'latest-dropped' } });
    expect(r.fail).toBe(true);
    expect(r.violations[0].detail).toContain('Python 3.9');
    expect(r.violations[0].detail).toContain('0.40.0');
  });

  it('no runtimeCompat data -> no violation', () => {
    const r = evaluatePolicy([finding({ name: 'clean' })], { failOn: { runtime: 'incompatible' } });
    expect(r.fail).toBe(false);
  });
});

describe('policyNeeds', () => {
  it('asks for latest only for license rules, health for min-health, runtime for runtime', () => {
    expect(policyNeeds({ failOn: { license: ['MIT'] } })).toEqual({ latest: true, health: false, runtime: false });
    expect(policyNeeds({ failOn: { minHealth: 5 } })).toEqual({ latest: false, health: true, runtime: false });
    expect(policyNeeds({ failOn: { suspiciousName: true } })).toEqual({ latest: false, health: false, runtime: false });
    expect(policyNeeds({ failOn: { runtime: 'incompatible' } })).toEqual({ latest: false, health: false, runtime: true });
  });
});

describe('loadPolicy', () => {
  it('reads the example config at the repo root', () => {
    const path = fileURLToPath(new URL('../../../preflight.config.json', import.meta.url));
    expect(loadPolicy(path).failOn?.suspiciousName).toBe(true);
  });

  it('returns an empty policy for a missing file', () => {
    expect(loadPolicy('/no/such/preflight.config.json')).toEqual({});
  });
});
