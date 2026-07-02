import { describe, expect, it } from 'vitest';

import { toCycloneDX } from '../src/sbom';
import { toSarif } from '../src/sarif';
import type { Report } from '../src/types';

const report: Report = {
  ecosystem: 'npm',
  path: 'package.json',
  total: 2,
  findings: [
    {
      name: '@scope/pkg',
      range: '^1',
      version: '1.2.3',
      dev: false,
      direct: true,
      vulns: [{ id: 'CVE-1', summary: 'bad thing', severity: 'high', cve: 'CVE-1', epss: 0.9, kev: true }],
      lockstep: { pinned: false },
      verdict: 'cve',
      reason: 'x',
    },
    {
      name: 'safe-pkg',
      range: '^2',
      version: '2.0.0',
      dev: false,
      direct: false,
      vulns: [],
      lockstep: { pinned: false },
      verdict: 'safe',
      reason: 'x',
    },
  ],
  summary: { malware: 0, cve: 1, incompatible: 0, pinned: 0, stale: 0, safe: 1 },
};

describe('toCycloneDX', () => {
  const bom = toCycloneDX(report) as {
    bomFormat: string;
    specVersion: string;
    components: { name: string; purl?: string; 'bom-ref': string }[];
    vulnerabilities?: {
      id: string;
      ratings: { severity: string }[];
      properties?: { name: string; value: string }[];
      affects: { ref: string }[];
    }[];
  };

  it('is a CycloneDX 1.6 doc with a component per dependency', () => {
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.components).toHaveLength(2);
    expect(bom.components.find((c) => c.name === '@scope/pkg')?.purl).toBe('pkg:npm/%40scope/pkg@1.2.3');
  });

  it('records vulnerabilities with EPSS/KEV and links them to the component', () => {
    expect(bom.vulnerabilities).toHaveLength(1);
    const v = bom.vulnerabilities![0];
    expect(v.id).toBe('CVE-1');
    expect(v.ratings[0].severity).toBe('high');
    expect(v.properties?.some((p) => p.name === 'cisa:kev')).toBe(true);
    expect(v.affects[0].ref).toBe('pkg:npm/%40scope/pkg@1.2.3');
  });
});

describe('toSarif', () => {
  const sarif = toSarif([report]) as {
    version: string;
    runs: {
      tool: { driver: { rules: { id: string; properties: Record<string, string> }[] } };
      results: { level: string; message: { text: string } }[];
    }[];
  };

  it('is SARIF 2.1.0 with one result per advisory', () => {
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].level).toBe('error'); // high → error
    expect(sarif.runs[0].results[0].message.text).toContain('actively exploited (CISA KEV)');
  });

  it('sets GitHub security-severity on the rule', () => {
    expect(sarif.runs[0].tool.driver.rules[0].properties['security-severity']).toBe('7.5');
  });
});
