import type { Ecosystem } from './types';

// deps.dev v3 — free, no key. The OpenSSF Scorecard lives on the *project* a package
// links to, so this is a 2-hop lookup (version -> project key -> scorecard).
// VERIFY the exact v3 paths + system casing against https://docs.deps.dev/api/v3/ before
// relying on this — it's wired behind the CLI's `--health` flag, not the default run.
const DEPSDEV = 'https://api.deps.dev/v3';

function system(ecosystem: Ecosystem): string {
  return ecosystem === 'npm' ? 'npm' : 'pypi';
}

/** OpenSSF Scorecard (0–10) for the project backing a package version, if available. */
export async function fetchScorecard(
  name: string,
  version: string,
  ecosystem: Ecosystem,
): Promise<number | undefined> {
  try {
    const sys = system(ecosystem);
    const verRes = await fetch(
      `${DEPSDEV}/systems/${sys}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
    );
    if (!verRes.ok) return undefined;
    const ver = (await verRes.json()) as {
      relatedProjects?: { projectKey?: { id?: string } }[];
    };
    const projectId = ver.relatedProjects?.[0]?.projectKey?.id;
    if (!projectId) return undefined;

    const projRes = await fetch(`${DEPSDEV}/projects/${encodeURIComponent(projectId)}`);
    if (!projRes.ok) return undefined;
    const proj = (await projRes.json()) as { scorecard?: { overallScore?: number } };
    return proj.scorecard?.overallScore;
  } catch {
    return undefined;
  }
}
