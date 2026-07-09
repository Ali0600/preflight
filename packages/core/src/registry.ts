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
  /** Sparse map of version -> upstream deprecation notice: npm's per-version `deprecated`
   * message, or "yanked from PyPI" for a release whose files are all yanked. Only versions
   * that ARE deprecated appear (most packages contribute nothing, so the cache stays small). */
  deprecated?: Record<string, string>;
}

/** npm's `deprecated` is a message string; a bare `true` appears in some old docs. An empty
 * string means "un-deprecated" (npm CLI ignores it too) — a false "deprecated" verdict is bad
 * advice, so only a real signal counts. */
function npmDeprecation(dep: unknown): string | undefined {
  if (dep === true) return 'deprecated upstream (no message given)';
  if (typeof dep === 'string' && dep.trim() !== '') return dep.trim();
  return undefined;
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
          versions?: Record<string, { deprecated?: unknown }>;
        };
        const license = typeof j.license === 'string' ? j.license : j.license?.type;
        const deprecated: Record<string, string> = {};
        for (const [v, meta] of Object.entries(j.versions ?? {})) {
          const msg = npmDeprecation(meta.deprecated);
          if (msg) deprecated[v] = msg;
        }
        return {
          latest: j['dist-tags']?.latest,
          lastPublish: j.time?.modified,
          license,
          deprecated: Object.keys(deprecated).length ? deprecated : undefined,
        };
      }
      const r = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
      if (r.status === 404) return {};
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = (await r.json()) as {
        info?: { version?: string; license?: string; classifiers?: string[] };
        urls?: { upload_time_iso_8601?: string }[];
        releases?: Record<
          string,
          { upload_time_iso_8601?: string; yanked?: boolean; yanked_reason?: string | null }[]
        >;
      };
      const latest = j.info?.version;
      const lastPublish =
        j.urls?.[0]?.upload_time_iso_8601 ??
        (latest ? j.releases?.[latest]?.[0]?.upload_time_iso_8601 : undefined);
      // PyPI has no "deprecated" concept — yanking (PEP 592) is its "stop using this" signal.
      // A release counts only when EVERY file is yanked (a partial yank targets one bad wheel).
      const deprecated: Record<string, string> = {};
      for (const [v, files] of Object.entries(j.releases ?? {})) {
        if (files.length === 0 || !files.every((f) => f.yanked)) continue;
        const reason = files.find((f) => f.yanked_reason)?.yanked_reason;
        deprecated[v] = reason ? `yanked from PyPI: ${reason}` : 'yanked from PyPI';
      }
      return {
        latest,
        lastPublish,
        license: pypiLicense(j.info),
        deprecated: Object.keys(deprecated).length ? deprecated : undefined,
      };
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
