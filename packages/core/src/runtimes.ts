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

/** Per-version runtime constraints from the npm registry or PyPI JSON API (both keyless). */
export async function fetchRuntimeMeta(name: string, ecosystem: Ecosystem): Promise<RuntimeMeta> {
  return cached(`runtimes:${ecosystem}:${name}`, async () => {
    try {
      if (ecosystem === 'npm') {
        // The abbreviated ("corgi") doc is a fraction of the full doc's size and
        // still carries per-version `engines`.
        const r = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
          headers: { Accept: 'application/vnd.npm.install-v1+json' },
        });
        if (!r.ok) return EMPTY;
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
      if (!r.ok) return EMPTY;
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
    } catch (err) {
      warn(`runtime metadata lookup failed for ${name}: ${(err as Error).message}`);
      return EMPTY;
    }
  });
}

/** Resolve runtime metadata for many packages in parallel. */
export async function fetchRuntimeMetaAll(
  names: string[],
  ecosystem: Ecosystem,
): Promise<Map<string, RuntimeMeta>> {
  const out = new Map<string, RuntimeMeta>();
  await Promise.all(
    names.map(async (name) => {
      out.set(name, await fetchRuntimeMeta(name, ecosystem));
    }),
  );
  return out;
}
