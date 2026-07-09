import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';

import { fetchHealth, type HealthInfo } from './depsdev';
import { fetchDownloads } from './downloads';
import { fetchRuntimeEol } from './eol';
import { fetchEpss } from './epss';
import { fetchKev } from './kev';
import { lockstepFor, presentFrameworks } from './lockstep';
import { parseManifest, parseManifestContent } from './manifest';
import { fetchRegistryAll } from './registry';
import { computeRuntimeCompat } from './runtime-compat';
import { fetchRuntimeMetaAll } from './runtimes';
import { typosquatOf } from './typosquat';
import type {
  DataSource,
  Dependency,
  Ecosystem,
  Finding,
  Manifest,
  Report,
  RuntimeEol,
  RuntimeName,
  RuntimeTarget,
  Verdict,
  Vuln,
} from './types';
import { fetchVulns } from './osv';
import { decideVerdict, runtimeLabel } from './verdict';

/** Thrown when the enumerated graph exceeds `AnalyzeOptions.maxDeps`. The message is
 * self-authored (safe to surface), so untrusted callers can map it to a 413 without leaking
 * internals. Guards the outbound fan-out on the public web endpoints (one 8 MB lockfile could
 * otherwise amplify into thousands of OSV/registry calls). */
export class GraphTooLargeError extends Error {
  constructor(readonly count: number, readonly max: number) {
    super(`Dependency graph too large: ${count} deps (max ${max}). Scan locally with the CLI instead.`);
    this.name = 'GraphTooLargeError';
  }
}

export interface AnalyzeOptions {
  /** Fetch each dep's latest version + last-publish date (enables the `stale` verdict). */
  latest?: boolean;
  /** Fetch each dep's OpenSSF Scorecard from deps.dev (extra 2-hop calls). */
  health?: boolean;
  /** Target runtimes to check installability against (enables the `incompatible` verdict).
   * The manifest's ecosystem picks which one applies: npm -> node, PyPI -> python. */
  runtimes?: Partial<Record<RuntimeName, RuntimeTarget>>;
  /** Cap the enumerated dependency graph — throws `GraphTooLargeError` above it, BEFORE any
   * network fan-out. Left unset by trusted callers (CLI/Action/fleet scan real repos); set by
   * the public web endpoints to bound abuse. */
  maxDeps?: number;
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

/**
 * Analyze an in-memory set of manifest files. Writes them to a throwaway temp dir so the npm
 * lockfile graph resolves (the full transitive scan), then runs `analyze`. Keyless — the caller
 * supplies the file contents (a web endpoint, a fleet scan), Preflight never reaches for a repo.
 * Pass e.g. `{ 'package.json': '…', 'package-lock.json': '…' }`.
 */
export async function analyzeFiles(
  files: Record<string, string>,
  opts: AnalyzeOptions = {},
): Promise<Report> {
  const dir = mkdtempSync(join(tmpdir(), 'preflight-'));
  const root = resolve(dir);
  try {
    let manifestPath: string | undefined;
    for (const [name, content] of Object.entries(files)) {
      const p = resolve(join(dir, name));
      // The keys come from an untrusted caller (the public /api/scan). A key like `../../x`
      // would otherwise write outside the temp dir — arbitrary file write. Reject anything that
      // escapes the sandbox; legitimate sub-paths (e.g. `backend/package.json`) resolve inside it.
      if (p !== root && !p.startsWith(root + sep)) {
        throw new Error(`Unsafe file path in request: ${name}`);
      }
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, content);
      if (/(^|\/)(package\.json|requirements[\w.-]*\.txt)$/i.test(name)) manifestPath ??= p;
    }
    if (!manifestPath) throw new Error('No package.json or requirements*.txt among the files');
    return await analyze(manifestPath, opts);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Core pipeline on a parsed manifest: OSV vulns + lockstep (+ latest/health) -> verdict -> report. */
export async function analyzeManifest(manifest: Manifest, opts: AnalyzeOptions = {}): Promise<Report> {
  const { dependencies, ecosystem } = manifest;

  // Bound the outbound fan-out before any network call: an untrusted caller (public /api/scan)
  // could otherwise submit a lockfile enumerating tens of thousands of packages, each of which
  // fans out to OSV/registry/deps.dev. Trusted callers leave `maxDeps` unset (unbounded).
  if (opts.maxDeps !== undefined && dependencies.length > opts.maxDeps) {
    throw new GraphTooLargeError(dependencies.length, opts.maxDeps);
  }

  // OSV scans the whole graph; latest-version + health only apply to deps you control directly
  // (you don't bump a transitive dep yourself), so scope those lookups to the direct set.
  const directDeps = dependencies.filter((d) => d.direct !== false);
  const directNames = [...new Set(directDeps.map((d) => d.name))];

  // Registry-style lookups (latest/health/runtimes/downloads/typosquat) only make sense for
  // package registries — an `actions` manifest gets OSV (+ KEV/EPSS) and the mutable-ref check.
  const registryEco = ecosystem !== 'actions';

  // Runtime installability only applies to deps you version yourself (direct), against
  // the runtime matching this manifest's ecosystem.
  const runtimeTarget = registryEco ? opts.runtimes?.[ecosystem === 'npm' ? 'node' : 'python'] : undefined;

  // Only frameworks actually present (by anchor package, e.g. `expo`, `next`) may claim
  // lockstep members — `react` in a Next-only manifest is not "Expo-coordinated" (#18).
  const frameworks = presentFrameworks(directNames);

  // Typosquat heuristic (offline) up-front, so download counts can put numbers behind any hit.
  // Only deps a human chose (direct) — transitive names are registry-real.
  // (For `actions` the curated list holds popular `owner/repo` uses — same attack, CI flavor.)
  const squatHits = new Map<string, string>(); // suspicious name -> the popular package it resembles
  for (const name of directNames) {
    const similarTo = typosquatOf(name, ecosystem);
    if (similarTo) squatHits.set(name, similarTo);
  }
  // Download counts are fetched ONLY where they inform something (bounded fan-out, also on the
  // public web endpoints): typosquat candidates + their targets always; direct deps under --health.
  const downloadNames = registryEco
    ? [...(opts.health ? directNames : []), ...squatHits.keys(), ...squatHits.values()]
    : [];

  // Data sources that fail to fetch this run are collected (not cached — see the fetchers) so a
  // green gate that ran with, say, KEV unavailable can announce "exploited-status unknown".
  // A per-call Set (not module state) keeps concurrent web requests from cross-contaminating.
  const degraded = new Set<string>();
  const onDegraded = (source: string): void => {
    degraded.add(source);
  };

  const [vulnMap, registryMap, healthMap, runtimeMap, runtimeEol, downloadsMap] = await Promise.all([
    fetchVulns(dependencies, ecosystem, onDegraded),
    registryEco && opts.latest ? fetchRegistryAll(directNames, ecosystem, onDegraded) : undefined,
    registryEco && opts.health ? fetchHealthAll(directDeps, ecosystem, onDegraded) : undefined,
    runtimeTarget ? fetchRuntimeMetaAll(directNames, ecosystem, onDegraded) : undefined,
    // One keyless call per product (24h-cached): is the target runtime itself end-of-life?
    runtimeTarget ? fetchRuntimeEol(runtimeTarget, onDegraded) : undefined,
    downloadNames.length > 0 ? fetchDownloads(downloadNames, ecosystem, onDegraded) : undefined,
  ]);
  await enrichExploitability(vulnMap, onDegraded); // EPSS + KEV — only fires when CVEs were found

  const findings: Finding[] = dependencies.map((d) => {
    const info = registryMap?.get(d.name);
    const health = healthMap?.get(d.name);
    const direct = d.direct !== false;
    const runtimeMeta = direct && runtimeTarget ? runtimeMap?.get(d.name) : undefined;
    const base = {
      name: d.name,
      range: d.range,
      version: d.version,
      dev: d.dev,
      direct,
      vulns: vulnMap.get(`${d.name}@${d.version}`) ?? [],
      lockstep: lockstepFor(d.name, frameworks),
      latest: info?.latest,
      lastPublish: info?.lastPublish,
      // Registry self-declared license first; deps.dev's detected SPDX (under --health) fills gaps.
      license: info?.license ?? health?.license,
      // Upstream deprecation notice for the *resolved* version (npm `deprecated` / PyPI yank).
      deprecated: d.version ? info?.deprecated?.[d.version] : undefined,
      health: health?.score,
      healthChecks: health?.checks?.filter((c) => c.score < 7), // surface only the weak spots
      installScript: d.installScript,
      provenance: health?.provenance,
      // Typosquat hit (precomputed) + weekly downloads for both sides when reachable — a
      // lookalike nobody installs next to a target everyone installs is the classic signature.
      suspiciousName:
        direct && squatHits.has(d.name)
          ? {
              similarTo: squatHits.get(d.name)!,
              downloadsPerWeek: downloadsMap?.get(d.name),
              targetDownloadsPerWeek: downloadsMap?.get(squatHits.get(d.name)!),
            }
          : undefined,
      // Adoption display for deps you chose, under --health.
      downloadsPerWeek: direct && opts.health ? downloadsMap?.get(d.name) : undefined,
      mutableRef: d.mutableRef,
      runtimeCompat: runtimeMeta
        ? computeRuntimeCompat({ range: d.range, version: d.version }, runtimeMeta, runtimeTarget!, ecosystem)
        : undefined,
    };
    const { verdict, reason } = decideVerdict(base);
    return { ...base, verdict, reason };
  });

  const summary: Record<Verdict, number> = {
    malware: 0,
    cve: 0,
    incompatible: 0,
    deprecated: 0,
    pinned: 0,
    stale: 0,
    safe: 0,
  };
  for (const f of findings) summary[f.verdict] += 1;

  return {
    ecosystem,
    path: manifest.path,
    total: findings.length,
    findings,
    summary,
    runtimeTarget,
    runtimeEol,
    lockfile: manifest.lockfile,
    degraded: degraded.size ? [...degraded] : undefined,
    sources: describeSources({
      ecosystem,
      dependencies,
      findings,
      degraded,
      opts,
      runtimeTarget,
      runtimeEol,
      directCount: directNames.length,
      downloadsRequested: new Set(downloadNames).size,
      downloadsFetched: downloadsMap?.size ?? 0,
    }),
  };
}

/** Build the per-source transparency ledger: which data sources ran, their reachability, and a
 * one-line result. Derived from what was actually queried (opts + which CVEs were found) and the
 * `degraded` set, so it never claims a source ran that didn't. Keeps every surface honest about
 * coverage — a clean scan should still show *what it checked*, not just "no findings". */
function describeSources(args: {
  ecosystem: Ecosystem;
  dependencies: Dependency[];
  findings: Finding[];
  degraded: Set<string>;
  opts: AnalyzeOptions;
  runtimeTarget?: RuntimeTarget;
  runtimeEol?: RuntimeEol;
  directCount: number;
  downloadsRequested: number;
  downloadsFetched: number;
}): DataSource[] {
  const {
    ecosystem,
    dependencies,
    findings,
    degraded,
    opts,
    runtimeTarget,
    runtimeEol,
    directCount,
    downloadsRequested,
    downloadsFetched,
  } = args;
  const down = (s: string): boolean => degraded.has(s);
  const registry = ecosystem === 'npm' ? 'npm registry' : 'PyPI';
  const sources: DataSource[] = [];

  // OSV — always consulted (a failed OSV querybatch throws before this runs, so reaching here
  // means the presence scan succeeded; only per-advisory detail fetches can degrade).
  // Actions manifests get their OWN row name: the check is different (package-level advisory
  // lookups on every `uses:`, ranges matched locally), and a distinct name keeps the Action's
  // run-level `aggregateSources` (one row per name) from letting a workflow's "scanned 0
  // versions" clobber a package manifest's real count.
  const scanned = dependencies.filter((d) => d.version).length;
  const allVulns = findings.flatMap((f) => f.vulns);
  const affected = findings.filter((f) => f.vulns.length > 0).length;
  const advisoriesTail = `${allVulns.length} advisor${allVulns.length === 1 ? 'y' : 'ies'}${affected ? ` in ${affected} package(s)` : ''}`;
  sources.push(
    ecosystem === 'actions'
      ? {
          name: 'OSV.dev (GitHub Actions advisories)',
          status: down('OSV advisory details') ? 'degraded' : 'ok',
          detail: down('OSV advisory details')
            ? `checked ${findings.length} action(s) — some lookups were unreachable this run`
            : `checked ${findings.length} action(s) → ${advisoriesTail}`,
        }
      : {
          name: 'OSV.dev (advisories)',
          status: down('OSV advisory details') ? 'degraded' : 'ok',
          detail: down('OSV advisory details')
            ? `scanned ${scanned} package version(s) — some advisory details were unreachable this run`
            : `scanned ${scanned} package version(s) → ${advisoriesTail}`,
        },
  );

  // KEV + EPSS — consulted only when at least one advisory carries a CVE id (enrichExploitability's gate).
  const cveIds = new Set(allVulns.map((v) => v.cve).filter((c): c is string => Boolean(c)));
  if (cveIds.size > 0) {
    // Count distinct CVEs (not advisory records — several advisories can share one CVE), so the
    // KEV and EPSS lines speak in the same units ("N of M CVEs").
    const kevCount = new Set(allVulns.filter((v) => v.kev && v.cve).map((v) => v.cve)).size;
    const epssScored = new Set(allVulns.filter((v) => v.epss !== undefined && v.cve).map((v) => v.cve)).size;
    const maxEpss = Math.max(0, ...allVulns.map((v) => v.epss ?? 0));
    sources.push({
      name: 'CISA KEV (exploited)',
      status: down('CISA KEV') ? 'degraded' : 'ok',
      detail: down('CISA KEV')
        ? 'unreachable — exploited-status unknown this run'
        : `${kevCount} of ${cveIds.size} CVE(s) confirmed actively exploited`,
    });
    sources.push({
      name: 'FIRST EPSS (exploit probability)',
      status: down('FIRST EPSS') ? 'degraded' : 'ok',
      detail: down('FIRST EPSS')
        ? 'unreachable — exploit-probability unknown this run'
        : `${epssScored} CVE(s) scored${maxEpss > 0 ? ` (max ${maxEpss.toFixed(2)})` : ''}`,
    });
  } else {
    sources.push({
      name: 'CISA KEV · FIRST EPSS (exploit prioritization)',
      status: 'skipped',
      detail: 'not needed — no CVEs to prioritize',
    });
  }

  // An actions manifest consults OSV (+ KEV/EPSS above) and the offline ref-pinning check —
  // registry-style rows (freshness/health/downloads/runtimes) don't apply to it.
  if (ecosystem === 'actions') {
    const mutable = findings.filter((f) => f.mutableRef).length;
    sources.push({
      name: 'ref pinning (offline)',
      status: 'ok',
      detail: mutable
        ? `${mutable} of ${findings.length} uses pinned to a mutable tag/branch — pin commit SHAs`
        : `all ${findings.length} uses pinned to full commit SHAs`,
    });
    return sources;
  }

  // Registry freshness + license + deprecation — only under --latest (or a license/deprecated policy).
  const deprecatedCount = findings.filter((f) => f.deprecated).length;
  sources.push(
    opts.latest
      ? {
          name: `${registry} (freshness · license · deprecation)`,
          status: down(registry) ? 'degraded' : 'ok',
          detail: down(registry)
            ? 'unreachable — latest versions/licenses/deprecations may be missing'
            : `latest version, license + deprecation for ${directCount} direct dep(s)${deprecatedCount ? ` → ${deprecatedCount} deprecated` : ''}`,
        }
      : {
          name: `${registry} (freshness · license · deprecation)`,
          status: 'skipped',
          detail: 'not run — enable with --latest / a license or deprecated policy',
        },
  );

  // OpenSSF Scorecard + build provenance — only under --health (one GetVersion call covers both).
  const attested = findings.filter((f) => f.provenance?.verified).length;
  sources.push(
    opts.health
      ? {
          name: 'deps.dev (Scorecard · provenance)',
          status: down('deps.dev') ? 'degraded' : 'ok',
          detail: down('deps.dev')
            ? 'unreachable — health scores/provenance may be missing'
            : `health score for ${findings.filter((f) => f.health !== undefined).length} dep(s)${attested ? ` · ${attested} with verified build provenance` : ''}`,
        }
      : {
          name: 'deps.dev (Scorecard · provenance)',
          status: 'skipped',
          detail: 'not run — enable with --health / a min-health policy',
        },
  );

  // Weekly downloads — consulted for typosquat candidates (+ their targets) and, under
  // --health, for direct deps. The download source differs per ecosystem.
  const dlSource = ecosystem === 'npm' ? 'npm downloads' : 'pypistats.org';
  const dlName = ecosystem === 'npm' ? 'npm downloads API (adoption)' : 'pypistats.org (adoption)';
  const squatCount = findings.filter((f) => f.suspiciousName).length;
  sources.push(
    downloadsRequested > 0
      ? {
          name: dlName,
          status: down(dlSource) ? 'degraded' : 'ok',
          detail: down(dlSource)
            ? 'unreachable — adoption/typosquat context missing this run'
            : `weekly downloads for ${downloadsFetched} of ${downloadsRequested} package(s)${squatCount ? ` · context for ${squatCount} suspicious name(s)` : ''}`,
        }
      : {
          name: dlName,
          status: 'skipped',
          detail: 'not needed — no suspicious names (--health adds adoption for direct deps)',
        },
  );

  // Runtime install-compatibility — only when a target runtime is set (uses registry engines /
  // Requires-Python, so it shares the registry's degraded label).
  if (runtimeTarget) {
    const incompat = findings.filter(
      (f) => f.runtimeCompat?.rangeUnsatisfiable || f.runtimeCompat?.resolvedIncompatible,
    ).length;
    sources.push({
      name: `${registry} (runtime compatibility)`,
      status: down(registry) ? 'degraded' : 'ok',
      detail: down(registry)
        ? `unreachable — compatibility with ${runtimeLabel(runtimeTarget)} unverified`
        : `checked ${directCount} direct dep(s) against ${runtimeLabel(runtimeTarget)}${incompat ? ` → ${incompat} incompatible` : ''}`,
    });

    // Runtime end-of-life — consulted whenever a target runtime is set.
    sources.push({
      name: 'endoflife.date (runtime EOL)',
      status: down('endoflife.date') ? 'degraded' : 'ok',
      detail: down('endoflife.date')
        ? `unreachable — EOL status of ${runtimeLabel(runtimeTarget)} unknown this run`
        : describeEol(runtimeTarget, runtimeEol),
    });
  } else {
    sources.push({
      name: 'endoflife.date (runtime EOL)',
      status: 'skipped',
      detail: 'not run — no target runtime declared or detected',
    });
  }

  return sources;
}

/** One ledger line for the runtime's EOL status (the source itself was reachable). */
function describeEol(target: RuntimeTarget, eol?: RuntimeEol): string {
  if (!eol) return `${runtimeLabel(target)} — release cycle unknown to endoflife.date`;
  const name = runtimeLabel(target);
  if (eol.isEol) return `${name} reached end-of-life${eol.eol ? ` on ${eol.eol}` : ''} — no security fixes`;
  if (eol.daysUntilEol !== undefined && eol.daysUntilEol <= 90) {
    return `${name} reaches end-of-life on ${eol.eol} (${eol.daysUntilEol} days)`;
  }
  return eol.eol ? `${name} supported until ${eol.eol}` : `${name} — no end-of-life date published`;
}

/** Attach EPSS (exploit probability) + CISA KEV (confirmed-exploited) to each found advisory.
 * Vuln objects are shared by reference across deps, so enriching the distinct set updates all. */
async function enrichExploitability(
  vulnMap: Map<string, Vuln[]>,
  onDegraded: (source: string) => void,
): Promise<void> {
  const vulns = [...new Set([...vulnMap.values()].flat())];
  const cves = vulns.map((v) => v.cve).filter((c): c is string => Boolean(c));
  if (cves.length === 0) return;
  const [epss, kev] = await Promise.all([fetchEpss(cves, onDegraded), fetchKev(onDegraded)]);
  for (const v of vulns) {
    if (!v.cve) continue;
    const e = epss.get(v.cve);
    if (e) {
      v.epss = e.epss;
      v.epssPercentile = e.percentile;
    }
    if (kev.has(v.cve)) v.kev = true;
  }
}

/** OpenSSF health (overall + per-check) for the versioned deps (deps.dev needs an exact version). */
async function fetchHealthAll(
  deps: Dependency[],
  ecosystem: Ecosystem,
  onDegraded: (source: string) => void,
): Promise<Map<string, HealthInfo>> {
  const out = new Map<string, HealthInfo>();
  await Promise.all(
    deps
      .filter((d) => d.version)
      .map(async (d) => {
        const health = await fetchHealth(d.name, d.version!, ecosystem, onDegraded);
        if (health.score !== undefined || health.checks?.length || health.license || health.provenance) {
          out.set(d.name, health);
        }
      }),
  );
  return out;
}

