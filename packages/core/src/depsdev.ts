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

export interface HealthInfo {
  /** Overall OpenSSF Scorecard (0–10). */
  score?: number;
  /** The security-relevant Scorecard checks (name + 0–10 score). */
  checks?: { name: string; score: number }[];
}

// The Scorecard checks that speak to supply-chain risk (the catalog has ~18; these are the ones
// worth surfacing). A score of -1 means "not run" and is dropped.
const SECURITY_CHECKS = new Set([
  'Dangerous-Workflow',
  'Token-Permissions',
  'Branch-Protection',
  'Code-Review',
  'Pinned-Dependencies',
  'Maintained',
  'Signed-Releases',
  'Vulnerabilities',
]);

/** OpenSSF Scorecard (overall + per-check) for the source repo backing a package version. */
export async function fetchHealth(
  name: string,
  version: string,
  ecosystem: Ecosystem,
): Promise<HealthInfo> {
  return cached(`depsdev:${ecosystem}:${name}:${version}`, async () => {
    try {
      const sys = system(ecosystem);
      const verRes = await fetch(
        `${DEPSDEV}/systems/${sys}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
      );
      if (!verRes.ok) return {};
      const ver = (await verRes.json()) as VersionResponse;
      const related = ver.relatedProjects ?? [];
      const projectId = (
        related.find((p) => p.relationType === 'SOURCE_REPO') ?? related[0]
      )?.projectKey?.id;
      if (!projectId) return {};

      const projRes = await fetch(`${DEPSDEV}/projects/${encodeURIComponent(projectId)}`);
      if (!projRes.ok) return {};
      const proj = (await projRes.json()) as {
        scorecard?: { overallScore?: number; checks?: { name?: string; score?: number }[] };
      };
      const checks = (proj.scorecard?.checks ?? [])
        .filter((c) => c.name && SECURITY_CHECKS.has(c.name) && (c.score ?? -1) >= 0)
        .map((c) => ({ name: c.name!, score: c.score! }));
      return { score: proj.scorecard?.overallScore, checks };
    } catch (err) {
      warn(`deps.dev lookup failed for ${name}@${version}: ${(err as Error).message}`);
      return {};
    }
  });
}
