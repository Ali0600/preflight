import { fetchScorecard } from './depsdev';
import { lockstepFor } from './lockstep';
import { parseManifest } from './manifest';
import { fetchRegistryAll } from './registry';
import type { Finding, Report, Verdict } from './types';
import { fetchVulns } from './osv';
import { decideVerdict } from './verdict';

export interface AnalyzeOptions {
  /** Fetch each dep's latest version + last-publish date (enables the `stale` verdict). */
  latest?: boolean;
  /** Fetch each dep's OpenSSF Scorecard from deps.dev (extra 2-hop calls). */
  health?: boolean;
}

/** Full pipeline: manifest -> OSV vulns + lockstep (+ latest/health) -> per-dep verdict -> report. */
export async function analyze(path: string, opts: AnalyzeOptions = {}): Promise<Report> {
  const manifest = parseManifest(path);
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

  return { ecosystem, path, total: findings.length, findings, summary };
}

/** Scorecards for the versioned deps (deps.dev needs an exact version). */
async function fetchHealth(
  deps: import('./types').Dependency[],
  ecosystem: import('./types').Ecosystem,
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
