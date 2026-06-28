import type { Ecosystem } from './types';

/** Latest published version, from the npm registry or PyPI JSON API (both keyless). */
export async function fetchLatest(name: string, ecosystem: Ecosystem): Promise<string | undefined> {
  try {
    if (ecosystem === 'npm') {
      const r = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
      if (!r.ok) return undefined;
      const j = (await r.json()) as { 'dist-tags'?: { latest?: string } };
      return j['dist-tags']?.latest;
    }
    const r = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
    if (!r.ok) return undefined;
    const j = (await r.json()) as { info?: { version?: string } };
    return j.info?.version;
  } catch {
    return undefined;
  }
}

export async function fetchLatestAll(
  names: string[],
  ecosystem: Ecosystem,
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  await Promise.all(
    names.map(async (name) => {
      const latest = await fetchLatest(name, ecosystem);
      if (latest) out.set(name, latest);
    }),
  );
  return out;
}
