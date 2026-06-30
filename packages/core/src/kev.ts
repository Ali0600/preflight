import { cached } from './cache';
import { warn } from './log';

// CISA Known Exploited Vulnerabilities — free, no key. A CVE here is *confirmed* exploited in the
// wild (certainty, not EPSS's probability). Verified feed shape: {vulnerabilities:[{cveID,…}]}.
const KEV_FEED =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** The set of CVE ids in CISA's KEV catalog. One cached fetch (the catalog is ~1600 entries). */
export async function fetchKev(): Promise<Set<string>> {
  const ids = await cached('kev:catalog', async () => {
    try {
      const r = await fetch(KEV_FEED);
      if (!r.ok) return [];
      const j = (await r.json()) as { vulnerabilities?: { cveID: string }[] };
      return (j.vulnerabilities ?? []).map((v) => v.cveID);
    } catch (err) {
      warn(`CISA KEV lookup failed: ${(err as Error).message}`);
      return [];
    }
  });
  return new Set(ids);
}
