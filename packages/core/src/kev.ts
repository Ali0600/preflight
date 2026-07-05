import { cached } from './cache';
import { warn } from './log';

// CISA Known Exploited Vulnerabilities — free, no key. A CVE here is *confirmed* exploited in the
// wild (certainty, not EPSS's probability). Verified feed shape: {vulnerabilities:[{cveID,…}]}.
const KEV_FEED =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** The set of CVE ids in CISA's KEV catalog. One cached fetch (the catalog is ~1600 entries).
 * On failure the throw inside `cached` prevents the empty result from being persisted — otherwise
 * a transient outage would poison the 24h cache and silently disarm `fail-level: kev` (an empty
 * KEV set marks zero CVEs as exploited). `onDegraded` lets the caller announce the gap. */
export async function fetchKev(onDegraded?: (source: string) => void): Promise<Set<string>> {
  try {
    const ids = await cached('kev:catalog', async () => {
      const r = await fetch(KEV_FEED);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as { vulnerabilities?: { cveID: string }[] };
      const list = (j.vulnerabilities ?? []).map((v) => v.cveID);
      // The catalog is never legitimately empty — an empty parse is a failure, not "no KEVs".
      if (list.length === 0) throw new Error('empty catalog');
      return list;
    });
    return new Set(ids);
  } catch (err) {
    warn(`CISA KEV lookup failed — exploited-status unknown this run: ${(err as Error).message}`);
    onDegraded?.('CISA KEV');
    return new Set();
  }
}
