import { cached } from './cache';
import { cvssV3Severity } from './cvss';
import { warn } from './log';
import { compareSemver, parseSemver } from './semver';
import type { Dependency, Ecosystem, Severity, Vuln } from './types';

// OSV.dev — free, no key. Request/response shapes verified against
// https://google.github.io/osv.dev/api/ and the OSV schema (https://ossf.github.io/osv-schema/).
const OSV = 'https://api.osv.dev';

/** Our ecosystem ids -> OSV's ecosystem names. */
const OSV_ECOSYSTEM: Record<Ecosystem, string> = {
  npm: 'npm',
  PyPI: 'PyPI',
  actions: 'GitHub Actions',
};

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
  // GitHub Actions takes a different path: OSV does NOT evaluate versioned queries for that
  // ecosystem (verified live 2026-07-09 — a version query for a known-affected release returns
  // {}), so we query per package and match the advisory ranges locally.
  if (ecosystem === 'actions') return fetchActionVulns(deps, onDegraded);

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
        const queries = group.map((d) => ({
          package: { name: d.name, ecosystem: OSV_ECOSYSTEM[ecosystem] },
          version: d.version,
        }));
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

/** One advisory for an action, with the ECOSYSTEM ranges + exact versions we match locally. */
interface ActionAdvisory {
  vuln: Vuln;
  /** Half-open spans from the advisory's ECOSYSTEM ranges (missing end = still affected). */
  spans: { introduced: string; fixed?: string; lastAffected?: string }[];
  /** Exact affected versions, when the advisory enumerates them instead. */
  versions: string[];
  /** True when the advisory carries no evaluable scoping at all (no ECOSYSTEM/GIT ranges, no
   * versions) — treated as affecting every version (fail-safe: typical of MAL compromises). */
  unscoped: boolean;
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: { type?: string; events?: { introduced?: string; fixed?: string; last_affected?: string }[] }[];
  versions?: string[];
}

/**
 * GitHub Actions path: OSV stores advisories for the "GitHub Actions" ecosystem but does not
 * evaluate versioned queries against their ECOSYSTEM ranges server-side — so we fetch every
 * advisory per action (`/v1/query`, paginated, cached 24h) and evaluate the ranges here with
 * the local semver machinery. Deps without an exact version (a mutable `@v4` tag or a SHA ref)
 * can't be range-matched — the mutable-ref warning covers those; only `unscoped` advisories
 * (no scoping data at all, e.g. a compromise MAL) still attach to them.
 */
async function fetchActionVulns(
  deps: Dependency[],
  onDegraded?: (source: string) => void,
): Promise<Map<string, Vuln[]>> {
  const out = new Map<string, Vuln[]>();
  const names = [...new Set(deps.map((d) => d.name))];
  await Promise.all(
    names.map(async (name) => {
      let advisories: ActionAdvisory[];
      try {
        advisories = await cached(`osv:actions:${name}`, () => queryActionAdvisories(name));
      } catch (err) {
        warn(`OSV lookup failed for action ${name}: ${(err as Error).message}`);
        onDegraded?.('OSV advisory details');
        return;
      }
      if (advisories.length === 0) return;
      for (const d of deps.filter((x) => x.name === name)) {
        const matched = advisories
          .filter((a) => actionAffected(a, d.version))
          .map((a) => a.vuln);
        if (matched.length > 0) out.set(`${d.name}@${d.version}`, matched);
      }
    }),
  );
  return out;
}

/** All advisories for one action from `/v1/query` (paginated), compacted for the cache. */
async function queryActionAdvisories(name: string): Promise<ActionAdvisory[]> {
  const raw: (OsvDetail & { affected?: OsvAffected[] })[] = [];
  let pageToken: string | undefined;
  do {
    const res = await fetch(`${OSV}/v1/query`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        package: { name, ecosystem: OSV_ECOSYSTEM.actions },
        ...(pageToken ? { page_token: pageToken } : {}),
      }),
    });
    if (!res.ok) throw new Error(`OSV query failed: ${res.status}`);
    const j = (await res.json()) as {
      vulns?: (OsvDetail & { affected?: OsvAffected[] })[];
      next_page_token?: string;
    };
    raw.push(...(j.vulns ?? []));
    pageToken = j.next_page_token;
  } while (pageToken);

  return raw.map((v) => {
    const mine = (v.affected ?? []).filter((a) => a.package?.name === name);
    const spans: ActionAdvisory['spans'] = [];
    let sawAnyRange = false;
    for (const a of mine) {
      for (const r of a.ranges ?? []) {
        sawAnyRange = true;
        if (r.type !== 'ECOSYSTEM') continue; // GIT ranges (commits) aren't evaluable here
        let open: ActionAdvisory['spans'][number] | undefined;
        for (const e of r.events ?? []) {
          if (e.introduced !== undefined) {
            open = { introduced: e.introduced };
            spans.push(open);
          } else if (open && e.fixed !== undefined) {
            open.fixed = e.fixed;
            open = undefined;
          } else if (open && e.last_affected !== undefined) {
            open.lastAffected = e.last_affected;
            open = undefined;
          }
        }
      }
    }
    const versions = mine.flatMap((a) => a.versions ?? []);
    const malicious = v.id.startsWith('MAL-');
    return {
      vuln: {
        id: v.id,
        summary: v.summary ?? v.details?.slice(0, 120) ?? v.id,
        severity: malicious ? ('critical' as Severity) : severityOf(v),
        cve: v.id.startsWith('CVE-') ? v.id : (v.aliases ?? []).find((a) => a.startsWith('CVE-')),
        malicious: malicious || undefined,
      },
      spans,
      versions,
      unscoped: !sawAnyRange && versions.length === 0,
    };
  });
}

/** OSV range events use partial versions ("0", "41", "46.0.1") — pad to full semver so the
 * strict parser accepts them ("41" -> 41.0.0). Undefined for anything non-numeric. */
function padSemver(s: string): ReturnType<typeof parseSemver> {
  const parts = s.trim().replace(/^v/, '').split('.');
  if (!parts.every((p) => /^\d+$/.test(p))) return parseSemver(s); // prerelease etc. — as-is
  while (parts.length < 3) parts.push('0');
  return parseSemver(parts.join('.'));
}

/** Evaluate one advisory against a used version (undefined = a mutable tag / SHA ref). */
function actionAffected(a: ActionAdvisory, version: string | undefined): boolean {
  if (a.unscoped) return true; // no scoping data — assume every version (fail-safe)
  if (!version) return false; // can't range-match a floating/SHA ref
  if (a.versions.some((v) => v === version || v === `v${version}`)) return true;
  const used = parseSemver(version);
  if (!used) return false;
  return a.spans.some((s) => {
    const intro = padSemver(s.introduced);
    if (intro && compareSemver(used, intro) < 0) return false;
    if (s.fixed !== undefined) {
      const fixed = padSemver(s.fixed);
      // An unparsable boundary can't prove the version is OUT of range — err on flagging.
      return fixed ? compareSemver(used, fixed) < 0 : true;
    }
    if (s.lastAffected !== undefined) {
      const last = padSemver(s.lastAffected);
      return last ? compareSemver(used, last) <= 0 : true;
    }
    return true; // introduced with no end — still affected
  });
}
