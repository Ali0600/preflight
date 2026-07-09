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
  /** SPDX 2.1 expressions, e.g. ["MIT"] — deps.dev detects these from the artifact, so they
   * fill gaps the registry's self-declared `license` field leaves (missing/free-text). */
  licenses?: string[];
  /** Build/publish attestations deps.dev found and checked for this version: npm Sigstore
   * provenance AND PyPI PEP 740 publish attestations both land here (shapes verified live). */
  attestations?: { type?: string; verified?: boolean; sourceRepository?: string }[];
  slsaProvenances?: { verified?: boolean; sourceRepository?: string }[];
}

/** Build-provenance summary for a package version (from deps.dev, which verifies the
 * signatures). `verified` = at least one attestation checked out; `sourceRepository` = the
 * repo the artifact was provably built from. */
export interface ProvenanceInfo {
  verified: boolean;
  sourceRepository?: string;
}

export interface HealthInfo {
  /** Overall OpenSSF Scorecard (0–10). */
  score?: number;
  /** The security-relevant Scorecard checks (name + 0–10 score). */
  checks?: { name: string; score: number }[];
  /** deps.dev's detected SPDX license expression — a fallback when the registry declares none. */
  license?: string;
  /** Present when the version ships a build/publish attestation (npm provenance / PEP 740). */
  provenance?: ProvenanceInfo;
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

/** Fold the version's attestations/slsaProvenances into one summary (absent = none shipped).
 * npm Sigstore provenance and PyPI PEP 740 publish attestations both appear in these arrays;
 * `verified` is deps.dev's own signature check, not our claim. */
function readProvenance(ver: VersionResponse): ProvenanceInfo | undefined {
  const all = [...(ver.attestations ?? []), ...(ver.slsaProvenances ?? [])];
  if (all.length === 0) return undefined;
  const verified = all.filter((a) => a.verified === true);
  return {
    verified: verified.length > 0,
    sourceRepository: (verified[0] ?? all[0]).sourceRepository,
  };
}

/** OpenSSF Scorecard (overall + per-check) for the source repo backing a package version.
 * A 404 (or no linked source repo) is a legitimate "no scorecard" ({} cached); any other failure
 * throws inside `cached` so the blank isn't persisted, and `onDegraded` announces the gap. */
export async function fetchHealth(
  name: string,
  version: string,
  ecosystem: Ecosystem,
  onDegraded?: (source: string) => void,
): Promise<HealthInfo> {
  try {
    return await cached(`depsdev:${ecosystem}:${name}:${version}`, async () => {
      const sys = system(ecosystem);
      const verRes = await fetch(
        `${DEPSDEV}/systems/${sys}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
      );
      if (verRes.status === 404) return {};
      if (!verRes.ok) throw new Error(`HTTP ${verRes.status}`);
      const ver = (await verRes.json()) as VersionResponse;
      const license = ver.licenses?.filter((l) => l && l !== 'non-standard').join(' AND ') || undefined;
      const provenance = readProvenance(ver);
      const related = ver.relatedProjects ?? [];
      const projectId = (
        related.find((p) => p.relationType === 'SOURCE_REPO') ?? related[0]
      )?.projectKey?.id;
      if (!projectId) return { license, provenance };

      const projRes = await fetch(`${DEPSDEV}/projects/${encodeURIComponent(projectId)}`);
      if (projRes.status === 404) return { license, provenance };
      if (!projRes.ok) throw new Error(`HTTP ${projRes.status}`);
      const proj = (await projRes.json()) as {
        scorecard?: { overallScore?: number; checks?: { name?: string; score?: number }[] };
      };
      const checks = (proj.scorecard?.checks ?? [])
        .filter((c) => c.name && SECURITY_CHECKS.has(c.name) && (c.score ?? -1) >= 0)
        .map((c) => ({ name: c.name!, score: c.score! }));
      return { score: proj.scorecard?.overallScore, checks, license, provenance };
    });
  } catch (err) {
    warn(`deps.dev lookup failed for ${name}@${version}: ${(err as Error).message}`);
    onDegraded?.('deps.dev');
    return {};
  }
}
