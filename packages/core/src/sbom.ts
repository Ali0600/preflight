import type { Ecosystem, Finding, Report, Severity } from './types';

// CycloneDX 1.6 SBOM (https://cyclonedx.org/) — a standard, tool-agnostic inventory of every
// component in the dependency graph plus the vulnerabilities affecting them. Consumable by
// OSV-Scanner, Dependency-Track, GitHub, etc.

const PURL_SYS: Record<Ecosystem, string> = { npm: 'npm', PyPI: 'pypi' };

/** Package URL (purl) for a finding, e.g. `pkg:npm/left-pad@1.3.0`. */
function purl(f: Finding, ecosystem: Ecosystem): string | undefined {
  if (!f.version) return undefined;
  const name = ecosystem === 'PyPI' ? f.name.toLowerCase() : f.name.replace(/^@/, '%40');
  return `pkg:${PURL_SYS[ecosystem]}/${name}@${f.version}`;
}

/** Stable component reference used to link a vulnerability back to the component it affects. */
function ref(f: Finding, ecosystem: Ecosystem): string {
  return purl(f, ecosystem) ?? `${f.name}@${f.version ?? f.range}`;
}

const CDX_SEVERITY: Record<Severity, string> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  unknown: 'unknown',
};

/** Build a CycloneDX 1.6 SBOM document from a Preflight report. */
export function toCycloneDX(report: Report): object {
  const { ecosystem } = report;

  const components = report.findings.map((f) => ({
    type: 'library',
    'bom-ref': ref(f, ecosystem),
    name: f.name,
    ...(f.version ? { version: f.version } : {}),
    ...(purl(f, ecosystem) ? { purl: purl(f, ecosystem) } : {}),
    ...(f.license ? { licenses: [{ license: { id: f.license } }] } : {}),
    properties: [
      { name: 'preflight:direct', value: String(f.direct !== false) },
      { name: 'preflight:verdict', value: f.verdict },
      ...(f.installScript ? [{ name: 'preflight:install-script', value: 'true' }] : []),
      ...(f.suspiciousName
        ? [{ name: 'preflight:typosquat-of', value: f.suspiciousName.similarTo }]
        : []),
    ],
  }));

  const vulnerabilities = report.findings.flatMap((f) =>
    f.vulns.map((v) => ({
      id: v.id,
      source: { name: 'OSV', url: `https://osv.dev/vulnerability/${v.id}` },
      ratings: [{ severity: CDX_SEVERITY[v.severity] }],
      ...(v.epss !== undefined || v.kev
        ? {
            properties: [
              ...(v.epss !== undefined ? [{ name: 'epss:score', value: String(v.epss) }] : []),
              ...(v.kev ? [{ name: 'cisa:kev', value: 'true' }] : []),
            ],
          }
        : {}),
      affects: [{ ref: ref(f, ecosystem) }],
    })),
  );

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'preflight', version: '0.1.0' }] },
      component: { type: 'application', name: report.path },
    },
    components,
    ...(vulnerabilities.length > 0 ? { vulnerabilities } : {}),
  };
}
