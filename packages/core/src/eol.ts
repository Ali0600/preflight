import { cached } from './cache';
import { warn } from './log';
import type { RuntimeEol, RuntimeName, RuntimeTarget } from './types';

// endoflife.date — free, keyless JSON. One fetch per product covers every release cycle
// (shape verified live: [{ cycle: "18", eol: "2025-04-30" | false, latest: "18.20.8" }, …];
// Node cycles are majors, Python cycles are major.minor).
const EOL_API = 'https://endoflife.date/api';

const PRODUCT: Record<RuntimeName, string> = { node: 'nodejs', python: 'python' };

/** A compact cycle entry — only what we cache (the full API row carries much more). */
interface Cycle {
  cycle: string;
  /** ISO date the cycle hits (or hit) EOL; `false` = no EOL declared; `true` = already EOL. */
  eol: string | boolean;
  latest?: string;
}

/** Map a (possibly partial) target version onto its release cycle: Node "18.19.0" → "18";
 * Python "3.9" → "3.9". A bare Python "3" spans many cycles — return undefined rather than
 * guess (a false "EOL" is bad advice, same conservatism as lockstep/typosquat). */
export function cycleOf(runtime: RuntimeName, version: string): string | undefined {
  const parts = version.split('.').filter((p) => /^\d+$/.test(p));
  if (runtime === 'node') return parts[0];
  return parts.length >= 2 ? `${parts[0]}.${parts[1]}` : undefined;
}

/** Resolve the target runtime's end-of-life status from endoflife.date.
 * Returns undefined when the version can't be mapped to a cycle, the cycle is unknown, or the
 * feed is unreachable (announced via `onDegraded` — never a silent gap). A failure throws inside
 * `cached()` so it is never persisted; an empty cycle list can never be legitimate for
 * nodejs/python, so it counts as failure too. */
export async function fetchRuntimeEol(
  target: RuntimeTarget,
  onDegraded?: (source: string) => void,
): Promise<RuntimeEol | undefined> {
  const cycle = cycleOf(target.runtime, target.version);
  if (!cycle) return undefined;
  try {
    const cycles = await cached(`eol:${target.runtime}`, async (): Promise<Cycle[]> => {
      const r = await fetch(`${EOL_API}/${PRODUCT[target.runtime]}.json`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as { cycle?: string | number; eol?: string | boolean; latest?: string }[];
      const rows = (Array.isArray(j) ? j : [])
        .filter((c) => c.cycle !== undefined && c.eol !== undefined)
        .map((c) => ({ cycle: String(c.cycle), eol: c.eol!, latest: c.latest }));
      // Node/Python always have published cycles — an empty list is an upstream failure
      // (same reasoning as the KEV catalog), and caching it would blind the check for 24h.
      if (rows.length === 0) throw new Error('empty cycle list');
      return rows;
    });
    const hit = cycles.find((c) => c.cycle === cycle);
    if (!hit) return undefined; // unknown cycle — don't guess
    const eolDate = typeof hit.eol === 'string' ? hit.eol : undefined;
    const daysUntilEol = eolDate
      ? Math.ceil((new Date(eolDate).getTime() - Date.now()) / (24 * 60 * 60 * 1000))
      : undefined;
    const isEol = hit.eol === true || (daysUntilEol !== undefined && daysUntilEol <= 0);
    return { runtime: target.runtime, cycle, eol: eolDate, isEol, daysUntilEol, latest: hit.latest };
  } catch (err) {
    warn(`endoflife.date lookup failed for ${target.runtime}: ${(err as Error).message}`);
    onDegraded?.('endoflife.date');
    return undefined;
  }
}
