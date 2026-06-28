import { fetchVulns } from './osv';
import { lockstepFor } from './lockstep';
import { parseManifest } from './manifest';
import { fetchLatestAll } from './registry';
import type { Finding, Report, Verdict } from './types';
import { decideVerdict } from './verdict';

export interface AnalyzeOptions {
  /** Also fetch each dep's latest published version (extra registry calls). */
  latest?: boolean;
}

/** Full pipeline: manifest -> OSV vulns + lockstep (+ latest) -> per-dep verdict -> report. */
export async function analyze(path: string, opts: AnalyzeOptions = {}): Promise<Report> {
  const manifest = parseManifest(path);
  const vulnMap = await fetchVulns(manifest.dependencies, manifest.ecosystem);
  const latestMap = opts.latest
    ? await fetchLatestAll(
        manifest.dependencies.map((d) => d.name),
        manifest.ecosystem,
      )
    : new Map<string, string>();

  const findings: Finding[] = manifest.dependencies.map((d) => {
    const base = {
      name: d.name,
      range: d.range,
      version: d.version,
      dev: d.dev,
      vulns: vulnMap.get(d.name) ?? [],
      lockstep: lockstepFor(d.name),
      latest: latestMap.get(d.name),
    };
    const { verdict, reason } = decideVerdict(base);
    return { ...base, verdict, reason };
  });

  const summary: Record<Verdict, number> = { safe: 0, pinned: 0, cve: 0, stale: 0 };
  for (const f of findings) summary[f.verdict] += 1;

  return { ecosystem: manifest.ecosystem, path, total: findings.length, findings, summary };
}
