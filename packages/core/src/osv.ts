import { cached } from './cache';
import { cvssV3Severity } from './cvss';
import { warn } from './log';
import type { Dependency, Ecosystem, Severity, Vuln } from './types';

// OSV.dev — free, no key. Request/response shapes verified against
// https://google.github.io/osv.dev/api/ and the OSV schema (https://ossf.github.io/osv-schema/).
const OSV = 'https://api.osv.dev';

// OSV's `querybatch` rejects very large batches with a 400 (an undocumented ~1000-query practical
// cap — a 1177-dep repo trips it), so we split into chunks of this size. Keeping it at 1000 means a
// manifest with ≤1000 deps is a single chunk with the same cache key as before (no cache churn).
const OSV_BATCH = 1000;

/** Split an array into consecutive groups of at most `size` (order preserved). */
function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

interface OsvDetail {
  id: string;
  summary?: string;
  details?: string;
  /** Other ids for the same advisory (CVE-…, GHSA-…); used to find the CVE for EPSS/KEV. */
  aliases?: string[];
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
 * Chunked `querybatch` POST(s) for presence (OSV 400s on very large batches), then fetch details
 * for the distinct vuln ids.
 * Returns a map keyed by `name@version` — a package can appear at several versions across the
 * dependency graph, so the name alone isn't unique. Deps without a resolved version are skipped.
 */
export async function fetchVulns(
  deps: Dependency[],
  ecosystem: Ecosystem,
  onDegraded?: (source: string) => void,
): Promise<Map<string, Vuln[]>> {
  const out = new Map<string, Vuln[]>();
  const items = new Map<string, { name: string; version: string }>();
  for (const d of deps) if (d.version) items.set(`${d.name}@${d.version}`, { name: d.name, version: d.version });
  const list = [...items.values()];
  if (list.length === 0) return out;

  // One querybatch per ≤1000-query chunk; Promise.all preserves chunk order and `.flat()`
  // concatenates in order, so `results[i]` still aligns with `list[i]`.
  const results = (
    await Promise.all(
      chunk(list, OSV_BATCH).map((group) => {
        const queries = group.map((d) => ({ package: { name: d.name, ecosystem }, version: d.version }));
        return cached(`osv:querybatch:${JSON.stringify(queries)}`, async () => {
          const res = await fetch(`${OSV}/v1/querybatch`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ queries }),
          });
          if (!res.ok) throw new Error(`OSV querybatch failed: ${res.status}`);
          const data = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
          return data.results ?? [];
        });
      }),
    )
  ).flat();

  const idsByItem = list
    .map((it, i) => ({ it, ids: (results[i]?.vulns ?? []).map((v) => v.id) }))
    .filter((x) => x.ids.length > 0);

  const uniqueIds = [...new Set(idsByItem.flatMap((x) => x.ids))];
  const details = new Map<string, Vuln>();
  await Promise.all(
    uniqueIds.map(async (id) => {
      try {
        const vuln = await cached(`osv:vuln:${id}`, async (): Promise<Vuln | undefined> => {
          const r = await fetch(`${OSV}/v1/vulns/${id}`);
          if (r.status === 404) return undefined; // advisory genuinely absent — cacheable
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          const v = (await r.json()) as OsvDetail;
          // OSV uses `MAL-…` ids for known-malicious packages (typosquats, compromised releases).
          const malicious = id.startsWith('MAL-');
          const cve = id.startsWith('CVE-') ? id : (v.aliases ?? []).find((a) => a.startsWith('CVE-'));
          return {
            id,
            summary: v.summary ?? v.details?.slice(0, 120) ?? id,
            severity: malicious ? 'critical' : severityOf(v),
            cve,
            malicious: malicious || undefined,
          };
        });
        if (vuln) details.set(id, vuln);
      } catch (err) {
        // A transient detail failure would otherwise cache an undefined and silently drop this
        // advisory (a `cve` could read `safe`) for 24h — don't cache it; announce the gap instead.
        warn(`OSV advisory ${id} lookup failed — dropped from this run: ${(err as Error).message}`);
        onDegraded?.('OSV advisory details');
      }
    }),
  );

  for (const { it, ids } of idsByItem) {
    out.set(
      `${it.name}@${it.version}`,
      ids.map((id) => details.get(id)).filter((v): v is Vuln => Boolean(v)),
    );
  }
  return out;
}
