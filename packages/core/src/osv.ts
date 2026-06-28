import type { Dependency, Ecosystem, Severity, Vuln } from './types';

// OSV.dev — free, no key. Verify request/response shapes against https://google.github.io/osv.dev/api/
const OSV = 'https://api.osv.dev';

interface OsvDetail {
  id: string;
  summary?: string;
  details?: string;
  database_specific?: { severity?: string };
}

const GHSA_SEVERITY: Record<string, Severity> = {
  low: 'low',
  moderate: 'medium',
  medium: 'medium',
  high: 'high',
  critical: 'critical',
};

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

  const res = await fetch(`${OSV}/v1/querybatch`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      queries: versioned.map((d) => ({ package: { name: d.name, ecosystem }, version: d.version })),
    }),
  });
  if (!res.ok) throw new Error(`OSV querybatch failed: ${res.status}`);
  const data = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
  const results = data.results ?? [];

  const idsByDep = versioned
    .map((dep, i) => ({ dep, ids: (results[i]?.vulns ?? []).map((v) => v.id) }))
    .filter((x) => x.ids.length > 0);

  const uniqueIds = [...new Set(idsByDep.flatMap((x) => x.ids))];
  const details = new Map<string, Vuln>();
  await Promise.all(
    uniqueIds.map(async (id) => {
      const r = await fetch(`${OSV}/v1/vulns/${id}`);
      if (!r.ok) return;
      const v = (await r.json()) as OsvDetail;
      details.set(id, {
        id,
        summary: v.summary ?? v.details?.slice(0, 120) ?? id,
        severity: GHSA_SEVERITY[(v.database_specific?.severity ?? '').toLowerCase()] ?? 'unknown',
      });
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
