import { cached } from './cache';
import { warn } from './log';
import type { Ecosystem } from './types';

// deps.dev v3 — free, no key. The OpenSSF Scorecard lives on the *project* a package
// links to, so this is a 2-hop lookup (version -> source-repo project -> scorecard).
// Shapes verified against https://docs.deps.dev/api/v3/: the {system} path segment is
// UPPERCASE (NPM/PYPI), and relatedProjects carry a relationType we filter on.
const DEPSDEV = 'https://api.deps.dev/v3';

function system(ecosystem: Ecosystem): string {
  return ecosystem === 'npm' ? 'NPM' : 'PYPI';
}

interface VersionResponse {
  relatedProjects?: { projectKey?: { id?: string }; relationType?: string }[];
}

/** OpenSSF Scorecard (0–10) for the source repo backing a package version, if available. */
export async function fetchScorecard(
  name: string,
  version: string,
  ecosystem: Ecosystem,
): Promise<number | undefined> {
  return cached(`depsdev:${ecosystem}:${name}:${version}`, async () => {
    try {
      const sys = system(ecosystem);
      const verRes = await fetch(
        `${DEPSDEV}/systems/${sys}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
      );
      if (!verRes.ok) return undefined;
      const ver = (await verRes.json()) as VersionResponse;
      const related = ver.relatedProjects ?? [];
      const projectId = (
        related.find((p) => p.relationType === 'SOURCE_REPO') ?? related[0]
      )?.projectKey?.id;
      if (!projectId) return undefined;

      const projRes = await fetch(`${DEPSDEV}/projects/${encodeURIComponent(projectId)}`);
      if (!projRes.ok) return undefined;
      const proj = (await projRes.json()) as { scorecard?: { overallScore?: number } };
      return proj.scorecard?.overallScore;
    } catch (err) {
      warn(`deps.dev lookup failed for ${name}@${version}: ${(err as Error).message}`);
      return undefined;
    }
  });
}
