import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';

import { fetchHealth, type HealthInfo } from './depsdev';
import { fetchEpss } from './epss';
import { fetchKev } from './kev';
import { lockstepFor, presentFrameworks } from './lockstep';
import { parseManifest, parseManifestContent } from './manifest';
import { fetchRegistryAll } from './registry';
import { computeRuntimeCompat } from './runtime-compat';
import { fetchRuntimeMetaAll } from './runtimes';
import { typosquatOf } from './typosquat';
import type {
  Dependency,
  Ecosystem,
  Finding,
  Manifest,
  Report,
  RuntimeName,
  RuntimeTarget,
  Verdict,
  Vuln,
} from './types';
import { fetchVulns } from './osv';
import { decideVerdict } from './verdict';

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

  // Runtime installability only applies to deps you version yourself (direct), against
  // the runtime matching this manifest's ecosystem.
  const runtimeTarget = opts.runtimes?.[ecosystem === 'npm' ? 'node' : 'python'];

  // Only frameworks actually present (by anchor package, e.g. `expo`, `next`) may claim
  // lockstep members — `react` in a Next-only manifest is not "Expo-coordinated" (#18).
  const frameworks = presentFrameworks(directNames);

  // Data sources that fail to fetch this run are collected (not cached — see the fetchers) so a
  // green gate that ran with, say, KEV unavailable can announce "exploited-status unknown".
  // A per-call Set (not module state) keeps concurrent web requests from cross-contaminating.
  const degraded = new Set<string>();
  const onDegraded = (source: string): void => {
    degraded.add(source);
  };

  const [vulnMap, registryMap, healthMap, runtimeMap] = await Promise.all([
    fetchVulns(dependencies, ecosystem, onDegraded),
    opts.latest ? fetchRegistryAll(directNames, ecosystem, onDegraded) : undefined,
    opts.health ? fetchHealthAll(directDeps, ecosystem, onDegraded) : undefined,
    runtimeTarget ? fetchRuntimeMetaAll(directNames, ecosystem, onDegraded) : undefined,
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
      license: info?.license,
      health: health?.score,
      healthChecks: health?.checks?.filter((c) => c.score < 7), // surface only the weak spots
      installScript: d.installScript,
      // Typosquat heuristic only on deps a human chose (direct); transitive names are registry-real.
      suspiciousName: direct ? typosquatHit(d.name, ecosystem) : undefined,
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
    lockfile: manifest.lockfile,
    degraded: degraded.size ? [...degraded] : undefined,
  };
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
        if (health.score !== undefined || health.checks?.length) out.set(d.name, health);
      }),
  );
  return out;
}

/** Wrap the typosquat heuristic into the Finding's `suspiciousName` shape. */
function typosquatHit(name: string, ecosystem: Ecosystem): { similarTo: string } | undefined {
  const similarTo = typosquatOf(name, ecosystem);
  return similarTo ? { similarTo } : undefined;
}
