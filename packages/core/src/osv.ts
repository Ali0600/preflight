import { cached } from './cache';
import { cvssV3Severity } from './cvss';
import type { Dependency, Ecosystem, Severity, Vuln } from './types';

// OSV.dev — free, no key. Request/response shapes verified against
// https://google.github.io/osv.dev/api/ and the OSV schema (https://ossf.github.io/osv-schema/).
const OSV = 'https://api.osv.dev';

interface OsvDetail {
  id: string;
  summary?: string;
  details?: string;
  /** Top-level CVSS scores; `score` is a vector string for CVSS types. */
  severity?: { type?: string; score?: string }[];
  /** Free-form; GitHub advisories put a qualitative label here (LOW/MODERATE/HIGH/CRITICAL). */
  database_specific?: { severity?: string };
}

const GHSA_SEVERITY: Record<string, Severity> = {
  low: 'low',
  moderate: 'medium',
  medium: 'medium',
  high: 'high',
  critical: 'critical',
};

/** Resolve a severity: prefer the GHSA qualitative label, fall back to the CVSS v3 vector. */
function severityOf(v: OsvDetail): Severity {
  const label = GHSA_SEVERITY[(v.database_specific?.severity ?? '').toLowerCase()];
  if (label) return label;
  for (const s of v.severity ?? []) {
    const fromVector = s.score ? cvssV3Severity(s.score) : undefined;
    if (fromVector) return fromVector;
  }
  return 'unknown';
}

/**
 * Look up known vulnerabilities for the given (versioned) deps.
 * One `querybatch` POST for presence, then fetch details for the distinct vuln ids.
 * Returns a map of dependency name -> vulns (only deps with a resolved version are queried).
 */
export async function fetchVulns(
  deps: Dependency[],
  ecosystem: Ecosystem,
): Promise<Map<string, Vuln[]>> {
  const out = new Map<string, Vuln[]>();
  const versioned = deps.filter((d): d is Dependency & { version: string } => Boolean(d.version));
  if (versioned.length === 0) return out;

  const queries = versioned.map((d) => ({
    package: { name: d.name, ecosystem },
    version: d.version,
  }));
  const results = await cached(`osv:querybatch:${JSON.stringify(queries)}`, async () => {
    const res = await fetch(`${OSV}/v1/querybatch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries }),
    });
    if (!res.ok) throw new Error(`OSV querybatch failed: ${res.status}`);
    const data = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
    return data.results ?? [];
  });

  const idsByDep = versioned
    .map((dep, i) => ({ dep, ids: (results[i]?.vulns ?? []).map((v) => v.id) }))
    .filter((x) => x.ids.length > 0);

  const uniqueIds = [...new Set(idsByDep.flatMap((x) => x.ids))];
  const details = new Map<string, Vuln>();
  await Promise.all(
    uniqueIds.map(async (id) => {
      const vuln = await cached(`osv:vuln:${id}`, async (): Promise<Vuln | undefined> => {
        const r = await fetch(`${OSV}/v1/vulns/${id}`);
        if (!r.ok) return undefined;
        const v = (await r.json()) as OsvDetail;
        return {
          id,
          summary: v.summary ?? v.details?.slice(0, 120) ?? id,
          severity: severityOf(v),
        };
      });
      if (vuln) details.set(id, vuln);
    }),
  );

  for (const { dep, ids } of idsByDep) {
    out.set(
      dep.name,
      ids.map((id) => details.get(id)).filter((v): v is Vuln => Boolean(v)),
    );
  }
  return out;
}
