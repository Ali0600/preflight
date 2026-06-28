import { cached } from './cache';
import { warn } from './log';
import type { Ecosystem } from './types';

export interface RegistryInfo {
  /** Latest published version (npm `dist-tags.latest` / PyPI `info.version`). */
  latest?: string;
  /** ISO timestamp of the most recent publish (npm `time.modified` / PyPI upload time). */
  lastPublish?: string;
}

/** Latest version + last-publish date, from the npm registry or PyPI JSON API (both keyless). */
export async function fetchRegistry(name: string, ecosystem: Ecosystem): Promise<RegistryInfo> {
  return cached(`registry:${ecosystem}:${name}`, async () => {
    try {
      if (ecosystem === 'npm') {
        const r = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
        if (!r.ok) return {};
        const j = (await r.json()) as {
          'dist-tags'?: { latest?: string };
          time?: { modified?: string };
        };
        return { latest: j['dist-tags']?.latest, lastPublish: j.time?.modified };
      }
      const r = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
      if (!r.ok) return {};
      const j = (await r.json()) as {
        info?: { version?: string };
        urls?: { upload_time_iso_8601?: string }[];
        releases?: Record<string, { upload_time_iso_8601?: string }[]>;
      };
      const latest = j.info?.version;
      const lastPublish =
        j.urls?.[0]?.upload_time_iso_8601 ??
        (latest ? j.releases?.[latest]?.[0]?.upload_time_iso_8601 : undefined);
      return { latest, lastPublish };
    } catch (err) {
      warn(`registry lookup failed for ${name}: ${(err as Error).message}`);
      return {};
    }
  });
}

/** Resolve registry info for many packages in parallel. */
export async function fetchRegistryAll(
  names: string[],
  ecosystem: Ecosystem,
): Promise<Map<string, RegistryInfo>> {
  const out = new Map<string, RegistryInfo>();
  await Promise.all(
    names.map(async (name) => {
      out.set(name, await fetchRegistry(name, ecosystem));
    }),
  );
  return out;
}
