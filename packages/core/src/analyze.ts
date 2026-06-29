import { fetchScorecard } from './depsdev';
import { lockstepFor } from './lockstep';
import { parseManifest, parseManifestContent } from './manifest';
import { fetchRegistryAll } from './registry';
import type { Dependency, Ecosystem, Finding, Manifest, Report, Verdict } from './types';
import { fetchVulns } from './osv';
import { decideVerdict } from './verdict';

export interface AnalyzeOptions {
  /** Fetch each dep's latest version + last-publish date (enables the `stale` verdict). */
  latest?: boolean;
  /** Fetch each dep's OpenSSF Scorecard from deps.dev (extra 2-hop calls). */
  health?: boolean;
}

/** Analyze a manifest file on disk (CLI / Action) — resolves npm lockfile versions. */
export async function analyze(path: string, opts: AnalyzeOptions = {}): Promise<Report> {
  return analyzeManifest(parseManifest(path), opts);
}

/** Analyze manifest *text* (web paste / Action base ref) — no filesystem access. */
export async function analyzeContent(
  filename: string,
  content: string,
  opts: AnalyzeOptions = {},
): Promise<Report> {
  return analyzeManifest(parseManifestContent(filename, content), opts);
}

/** Core pipeline on a parsed manifest: OSV vulns + lockstep (+ latest/health) -> verdict -> report. */
export async function analyzeManifest(manifest: Manifest, opts: AnalyzeOptions = {}): Promise<Report> {
  const { dependencies, ecosystem } = manifest;

  const [vulnMap, registryMap, healthMap] = await Promise.all([
    fetchVulns(dependencies, ecosystem),
    opts.latest ? fetchRegistryAll(dependencies.map((d) => d.name), ecosystem) : undefined,
    opts.health ? fetchHealth(dependencies, ecosystem) : undefined,
  ]);

  const findings: Finding[] = dependencies.map((d) => {
    const info = registryMap?.get(d.name);
    const base = {
      name: d.name,
      range: d.range,
      version: d.version,
      dev: d.dev,
      vulns: vulnMap.get(d.name) ?? [],
      lockstep: lockstepFor(d.name),
      latest: info?.latest,
      lastPublish: info?.lastPublish,
      health: healthMap?.get(d.name),
    };
    const { verdict, reason } = decideVerdict(base);
    return { ...base, verdict, reason };
  });

  const summary: Record<Verdict, number> = { safe: 0, pinned: 0, cve: 0, stale: 0 };
  for (const f of findings) summary[f.verdict] += 1;

  return { ecosystem, path: manifest.path, total: findings.length, findings, summary };
}

/** Scorecards for the versioned deps (deps.dev needs an exact version). */
async function fetchHealth(
  deps: Dependency[],
  ecosystem: Ecosystem,
): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  await Promise.all(
    deps
      .filter((d) => d.version)
      .map(async (d) => {
        const score = await fetchScorecard(d.name, d.version!, ecosystem);
        if (score !== undefined) out.set(d.name, score);
      }),
  );
  return out;
}
