import type { Report, Severity } from './types';

// SARIF 2.1.0 (https://sarifweb.azurewebsites.net/) — the format GitHub code scanning ingests, so
// Preflight findings appear in a repo's Security tab. One result per (dependency, advisory).

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  unknown: 'warning',
};

// GitHub reads `security-severity` (a CVSS-like number) to colour the alert.
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '7.5',
  medium: '5.0',
  low: '2.0',
  unknown: '0.0',
};

/** Build a SARIF 2.1.0 log from one or more reports (the Action scans several manifests). */
export function toSarif(reports: Report[]): object {
  const rules = new Map<string, object>();
  const results: object[] = [];

  for (const report of reports) {
    for (const f of report.findings) {
      for (const v of f.vulns) {
        if (!rules.has(v.id)) {
          rules.set(v.id, {
            id: v.id,
            name: v.malicious ? 'MaliciousPackage' : 'KnownVulnerability',
            shortDescription: { text: v.summary.slice(0, 240) },
            helpUri: `https://osv.dev/vulnerability/${v.id}`,
            properties: { 'security-severity': SECURITY_SEVERITY[v.severity] },
          });
        }
        const exploited = v.kev ? ' — actively exploited (CISA KEV)' : '';
        results.push({
          ruleId: v.id,
          level: v.malicious ? 'error' : LEVEL[v.severity],
          message: { text: `${f.name}@${f.version ?? f.range}: ${v.summary}${exploited}` },
          locations: [{ physicalLocation: { artifactLocation: { uri: report.path } } }],
        });
      }
    }
  }

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Preflight',
            informationUri: 'https://github.com/Ali0600/preflight',
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}
