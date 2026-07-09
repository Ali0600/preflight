import { cached } from './cache';
import { warn } from './log';
import type { Ecosystem } from './types';

// Weekly download counts — the adoption signal. Both endpoints are free and keyless.
// Shapes verified live (2026-07-09):
//   npm bulk:   GET api.npmjs.org/downloads/point/last-week/a,b -> { a: {downloads}, b: {…}|null }
//   npm single: GET …/last-week/@scope%2Fname               -> { downloads, package }  (no outer key)
//   PyPI:       GET pypistats.org/api/packages/{p}/recent   -> { data: { last_week } }
// npm bulk caps at 128 packages per request and does NOT accept scoped names — those (and all
// PyPI names) are fetched individually.
const NPM_API = 'https://api.npmjs.org/downloads/point/last-week';
const PYPISTATS = 'https://pypistats.org/api/packages';

const NPM_BULK_MAX = 128;

/** Weekly downloads for the given packages. Missing/unknown packages simply have no entry
 * (a 404 / bulk `null` is a legitimate, cacheable "not a package"); a failed request throws
 * inside `cached()` (never persisted) and is announced via `onDegraded` — callers degrade to
 * whatever offline signal they were enriching. */
export async function fetchDownloads(
  names: string[],
  ecosystem: Ecosystem,
  onDegraded?: (source: string) => void,
): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const unique = [...new Set(names)];
  if (unique.length === 0) return out;

  if (ecosystem === 'npm') {
    const scoped = unique.filter((n) => n.startsWith('@'));
    const plain = unique.filter((n) => !n.startsWith('@'));
    const jobs: Promise<void>[] = [];
    for (let i = 0; i < plain.length; i += NPM_BULK_MAX) {
      const chunk = plain.slice(i, i + NPM_BULK_MAX);
      jobs.push(npmBulk(chunk, out, onDegraded));
    }
    for (const name of scoped) jobs.push(npmSingle(name, out, onDegraded));
    await Promise.all(jobs);
    return out;
  }

  await Promise.all(unique.map((name) => pypiSingle(name, out, onDegraded)));
  return out;
}

async function npmBulk(
  chunk: string[],
  out: Map<string, number>,
  onDegraded?: (source: string) => void,
): Promise<void> {
  try {
    const rows = await cached(`downloads:npm:${chunk.join(',')}`, async () => {
      const r = await fetch(`${NPM_API}/${chunk.map(encodeURIComponent).join(',')}`);
      if (r.status === 404) return {}; // none of these exist — legit empty
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as Record<string, { downloads?: number } | null> & {
        downloads?: number;
      };
      // A single-name request returns the flat single shape (no outer package key).
      if (chunk.length === 1 && typeof j.downloads === 'number') {
        return { [chunk[0]]: j.downloads };
      }
      const counts: Record<string, number> = {};
      for (const [name, row] of Object.entries(j)) {
        if (row && typeof row === 'object' && typeof row.downloads === 'number') {
          counts[name] = row.downloads;
        }
      }
      return counts;
    });
    for (const [name, n] of Object.entries(rows)) out.set(name, n);
  } catch (err) {
    warn(`npm downloads lookup failed: ${(err as Error).message}`);
    onDegraded?.('npm downloads');
  }
}

async function npmSingle(
  name: string,
  out: Map<string, number>,
  onDegraded?: (source: string) => void,
): Promise<void> {
  try {
    const n = await cached(`downloads:npm:${name}`, async () => {
      const r = await fetch(`${NPM_API}/${encodeURIComponent(name)}`);
      if (r.status === 404) return null; // not a package — legit empty
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as { downloads?: number };
      return typeof j.downloads === 'number' ? j.downloads : null;
    });
    if (n !== null) out.set(name, n);
  } catch (err) {
    warn(`npm downloads lookup failed for ${name}: ${(err as Error).message}`);
    onDegraded?.('npm downloads');
  }
}

async function pypiSingle(
  name: string,
  out: Map<string, number>,
  onDegraded?: (source: string) => void,
): Promise<void> {
  try {
    const n = await cached(`downloads:pypi:${name}`, async () => {
      const r = await fetch(`${PYPISTATS}/${encodeURIComponent(name.toLowerCase())}/recent`);
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as { data?: { last_week?: number } };
      return typeof j.data?.last_week === 'number' ? j.data.last_week : null;
    });
    if (n !== null) out.set(name, n);
  } catch (err) {
    warn(`pypistats lookup failed for ${name}: ${(err as Error).message}`);
    onDegraded?.('pypistats.org');
  }
}
