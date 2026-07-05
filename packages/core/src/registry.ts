import { cached } from './cache';
import { warn } from './log';
import type { Ecosystem } from './types';

export interface RegistryInfo {
  /** Latest published version (npm `dist-tags.latest` / PyPI `info.version`). */
  latest?: string;
  /** ISO timestamp of the most recent publish (npm `time.modified` / PyPI upload time). */
  lastPublish?: string;
  /** Declared license id, e.g. "MIT" / "GPL-3.0" (npm `license` / PyPI classifier). */
  license?: string;
}

/** Pull a short license id from a PyPI `License :: OSI Approved :: X License` classifier. */
function pypiLicense(info?: { license?: string; classifiers?: string[] }): string | undefined {
  const cls = (info?.classifiers ?? []).find((c) => c.startsWith('License ::'));
  if (cls) return cls.split('::').pop()?.replace(/License$/i, '').trim() || cls;
  const lic = info?.license?.trim();
  return lic && lic.length <= 40 ? lic : undefined; // skip full license text dumped into `license`
}

/** Latest version + last-publish date, from the npm registry or PyPI JSON API (both keyless).
 * A 404 is a legitimate "no such package" ({} is cached); any other failure throws inside `cached`
 * so the blank isn't persisted, and `onDegraded` announces that staleness/license may be missing. */
export async function fetchRegistry(
  name: string,
  ecosystem: Ecosystem,
  onDegraded?: (source: string) => void,
): Promise<RegistryInfo> {
  try {
    return await cached(`registry:${ecosystem}:${name}`, async () => {
      if (ecosystem === 'npm') {
        const r = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
        if (r.status === 404) return {}; // package doesn't exist — legit empty, cacheable
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j = (await r.json()) as {
          'dist-tags'?: { latest?: string };
          time?: { modified?: string };
          license?: string | { type?: string };
        };
        const license = typeof j.license === 'string' ? j.license : j.license?.type;
        return { latest: j['dist-tags']?.latest, lastPublish: j.time?.modified, license };
      }
      const r = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
      if (r.status === 404) return {};
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as {
        info?: { version?: string; license?: string; classifiers?: string[] };
        urls?: { upload_time_iso_8601?: string }[];
        releases?: Record<string, { upload_time_iso_8601?: string }[]>;
      };
      const latest = j.info?.version;
      const lastPublish =
        j.urls?.[0]?.upload_time_iso_8601 ??
        (latest ? j.releases?.[latest]?.[0]?.upload_time_iso_8601 : undefined);
      return { latest, lastPublish, license: pypiLicense(j.info) };
    });
  } catch (err) {
    warn(`registry lookup failed for ${name}: ${(err as Error).message}`);
    onDegraded?.(ecosystem === 'npm' ? 'npm registry' : 'PyPI');
    return {};
  }
}

/** Resolve registry info for many packages in parallel. */
export async function fetchRegistryAll(
  names: string[],
  ecosystem: Ecosystem,
  onDegraded?: (source: string) => void,
): Promise<Map<string, RegistryInfo>> {
  const out = new Map<string, RegistryInfo>();
  await Promise.all(
    names.map(async (name) => {
      out.set(name, await fetchRegistry(name, ecosystem, onDegraded));
    }),
  );
  return out;
}
