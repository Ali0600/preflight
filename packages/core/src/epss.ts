import { cached } from './cache';
import { warn } from './log';

export interface EpssScore {
  /** Probability (0–1) the CVE is exploited in the next 30 days. */
  epss: number;
  /** Where that probability ranks among all scored CVEs (0–1). */
  percentile: number;
}

// FIRST EPSS — free, no key. Verified: GET api.first.org/data/v1/epss?cve=A,B → {data:[{cve,
// epss, percentile}]} (epss/percentile are strings). CVSS says how bad; EPSS says how *likely*.
const EPSS = 'https://api.first.org/data/v1/epss';

/** Exploit-prediction scores for the given CVE ids, batched (≤100/request). */
export async function fetchEpss(cveIds: string[]): Promise<Map<string, EpssScore>> {
  const out = new Map<string, EpssScore>();
  const ids = [...new Set(cveIds.filter((id) => id.startsWith('CVE-')))];
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    const rows = await cached(`epss:${chunk.join(',')}`, async () => {
      try {
        const r = await fetch(`${EPSS}?cve=${chunk.join(',')}`);
        if (!r.ok) return [];
        const j = (await r.json()) as { data?: { cve: string; epss: string; percentile: string }[] };
        return j.data ?? [];
      } catch (err) {
        warn(`EPSS lookup failed: ${(err as Error).message}`);
        return [];
      }
    });
    for (const d of rows) out.set(d.cve, { epss: Number(d.epss), percentile: Number(d.percentile) });
  }
  return out;
}
