import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

// Small disk cache for the keyless API calls (OSV / npm / PyPI / deps.dev). Re-runs of
// `preflight check` hit the same endpoints; caching respects rate limits and makes the
// second run effectively instant. Values are wrapped in an envelope so `undefined`/`null`
// round-trip through JSON cleanly (a bare `undefined` would serialize to nothing).

const DIR = '.preflight-cache';
const TTL_MS = 24 * 60 * 60 * 1000; // 24h

let enabled = true;

/** Toggle the disk cache (CLI `--no-cache`). When off, `cached` always calls through. */
export function setCacheEnabled(value: boolean): void {
  enabled = value;
}

interface Envelope<T> {
  v: T;
}

function fileFor(key: string): string {
  const hash = createHash('sha256').update(key).digest('hex').slice(0, 32);
  return join(DIR, `${hash}.json`);
}

/**
 * Return a cached value for `key`, or compute + persist it. A cache entry is reused when
 * it exists and is younger than the 24h TTL; a corrupt or stale file falls through to a
 * fresh compute. Cache I/O never throws — a broken cache degrades to a normal fetch.
 */
export async function cached<T>(key: string, compute: () => Promise<T>): Promise<T> {
  if (!enabled) return compute();
  const file = fileFor(key);
  try {
    if (existsSync(file) && Date.now() - statSync(file).mtimeMs < TTL_MS) {
      return (JSON.parse(readFileSync(file, 'utf8')) as Envelope<T>).v;
    }
  } catch {
    // corrupt/unreadable cache entry — fall through and recompute
  }
  const value = await compute();
  try {
    mkdirSync(DIR, { recursive: true });
    writeFileSync(file, JSON.stringify({ v: value } satisfies Envelope<T>));
  } catch {
    // best-effort cache write; never fail the run because we couldn't persist
  }
  return value;
}
