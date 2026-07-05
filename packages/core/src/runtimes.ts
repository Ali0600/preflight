import { cached } from './cache';
import { warn } from './log';
import type { Ecosystem } from './types';

// Per-version runtime constraints for a package: npm `engines.node` / PyPI
// `Requires-Python`. One fetch per package (the npm "corgi" abbreviated doc and
// PyPI's legacy JSON both carry the whole version history), cached compact.

export interface RuntimeMeta {
  /** version -> declared runtime constraint; null = version declares no constraint. */
  constraints: Record<string, string | null>;
  latest?: string;
}

const EMPTY: RuntimeMeta = { constraints: {} };

/** Per-version runtime constraints from the npm registry or PyPI JSON API (both keyless).
 * A 404 is a legitimate "no such package" (EMPTY cached); any other failure throws inside `cached`
 * so the blank isn't persisted (a cached blank would silently drop the `incompatible` check for
 * 24h), and `onDegraded` announces it. */
export async function fetchRuntimeMeta(
  name: string,
  ecosystem: Ecosystem,
  onDegraded?: (source: string) => void,
): Promise<RuntimeMeta> {
  try {
    return await cached(`runtimes:${ecosystem}:${name}`, async () => {
      if (ecosystem === 'npm') {
        // The abbreviated ("corgi") doc is a fraction of the full doc's size and
        // still carries per-version `engines`.
        const r = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
          headers: { Accept: 'application/vnd.npm.install-v1+json' },
        });
        if (r.status === 404) return EMPTY;
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j = (await r.json()) as {
          'dist-tags'?: { latest?: string };
          versions?: Record<string, { engines?: { node?: string } }>;
        };
        const constraints: Record<string, string | null> = {};
        for (const [v, meta] of Object.entries(j.versions ?? {})) {
          constraints[v] = meta.engines?.node ?? null;
        }
        return { constraints, latest: j['dist-tags']?.latest };
      }
      const r = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
      if (r.status === 404) return EMPTY;
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as {
        info?: { version?: string };
        releases?: Record<string, { requires_python?: string | null; yanked?: boolean }[]>;
      };
      const constraints: Record<string, string | null> = {};
      for (const [v, files] of Object.entries(j.releases ?? {})) {
        const live = (files ?? []).filter((f) => !f.yanked);
        if (live.length === 0) continue; // no installable files (fully yanked / empty)
        constraints[v] = live.find((f) => f.requires_python != null)?.requires_python ?? null;
      }
      return { constraints, latest: j.info?.version };
    });
  } catch (err) {
    warn(`runtime metadata lookup failed for ${name}: ${(err as Error).message}`);
    onDegraded?.(ecosystem === 'npm' ? 'npm registry' : 'PyPI');
    return EMPTY;
  }
}

/** Resolve runtime metadata for many packages in parallel. */
export async function fetchRuntimeMetaAll(
  names: string[],
  ecosystem: Ecosystem,
  onDegraded?: (source: string) => void,
): Promise<Map<string, RuntimeMeta>> {
  const out = new Map<string, RuntimeMeta>();
  await Promise.all(
    names.map(async (name) => {
      out.set(name, await fetchRuntimeMeta(name, ecosystem, onDegraded));
    }),
  );
  return out;
}
