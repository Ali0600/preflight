// Shared types for the Preflight engine. The CLI, GitHub Action, and web dashboard
// all consume these — keep this the single source of truth.

export type Ecosystem = 'npm' | 'PyPI';

export type Severity = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export type Verdict = 'malware' | 'cve' | 'incompatible' | 'pinned' | 'stale' | 'safe';

export interface Dependency {
  name: string;
  /** Version range as declared in the manifest, e.g. "^1.2.0" or ">=2,<3". */
  range: string;
  /** Resolved/installed version, when a lockfile was available (drives OSV queries). */
  version?: string;
  /** A devDependency (direct) or only reachable via devDependencies (transitive —
   * the npm lockfile's `dev` flag). Build-time scope, absent from the shipped artifact. */
  dev: boolean;
  /** Declared in the manifest (`true`) vs pulled in transitively from the lockfile (`false`).
   * Optional so hand-built objects/tests default to direct; the parser always sets it. */
  direct?: boolean;
  /** Runs a pre/post/install script (npm lockfile `hasInstallScript`) — code on `npm install`. */
  installScript?: boolean;
}

export interface Manifest {
  ecosystem: Ecosystem;
  path: string;
  dependencies: Dependency[];
  /** npm only: whether a lockfile expanded the graph (`false` = declared/direct deps only). */
  lockfile?: boolean;
}

export interface Vuln {
  id: string;
  summary: string;
  severity: Severity;
  /** The CVE alias (e.g. "CVE-2021-44228"), when the advisory has one — keys EPSS/KEV lookups. */
  cve?: string;
  /** Exploit-prediction probability 0–1 (FIRST EPSS), when known. */
  epss?: number;
  /** EPSS percentile 0–1. */
  epssPercentile?: number;
  /** In CISA's Known Exploited Vulnerabilities catalog (confirmed exploited in the wild). */
  kev?: boolean;
  /** A malicious-package advisory (OSV `MAL-…`), not a flaw in a legitimate package. */
  malicious?: boolean;
}

export interface LockstepInfo {
  /** True when the package is part of a framework's coordinated version set. */
  pinned: boolean;
  framework?: string; // e.g. "Expo"
  tool?: string; // the framework's own upgrade tool, e.g. "npx expo install"
}

export type RuntimeName = 'node' | 'python';

/** A target runtime the manifest must install on, e.g. node "18" or python "3.9". */
export interface RuntimeTarget {
  runtime: RuntimeName;
  /** Possibly-partial version: "18" means the whole 18.x series, "3.9" the 3.9.x series. */
  version: string;
  /** Where the target came from, for messages: "--python flag", ".nvmrc", "preflight.config.json". */
  source: string;
  /** Flag/config targets are explicit; auto-detected ones warn without failing builds. */
  explicit: boolean;
}

/** How a dependency relates to a target runtime (absent = fully compatible). */
export interface RuntimeCompat {
  target: RuntimeTarget;
  /** No version satisfying the declared range installs on the target (the bad-floor case). */
  rangeUnsatisfiable: boolean;
  /** The locked/pinned version itself doesn't install on the target. */
  resolvedIncompatible: boolean;
  /** The newest release dropped the target — the next auto-bump will break. */
  latestIncompatible: boolean;
  /** Highest version that still installs on the target (floor / downgrade advice). */
  maxCompatible?: string;
  /** Lowest version above maxCompatible — the auto-updater ignore boundary. */
  firstIncompatible?: string;
  /** The declared constraint that excludes the target (e.g. ">=3.10"), for messages. */
  constraint?: string;
}

export interface Finding {
  name: string;
  range: string;
  version?: string;
  dev: boolean;
  /** `false` when the package is a transitive (indirect) dependency. Defaults to direct. */
  direct?: boolean;
  vulns: Vuln[];
  lockstep: LockstepInfo;
  latest?: string;
  /** ISO timestamp of the dep's most recent publish (drives the `stale` verdict). */
  lastPublish?: string;
  /** OpenSSF Scorecard (0–10) from deps.dev, when `--health` is requested. */
  health?: number;
  /** Failing security-relevant Scorecard checks (name + 0–10 score), when `--health` is requested. */
  healthChecks?: { name: string; score: number }[];
  /** True when the package runs an install script (npm) — a supply-chain code-execution surface. */
  installScript?: boolean;
  /** SPDX-ish license id (e.g. "MIT", "GPL-3.0"), when `--latest` is requested. */
  license?: string;
  /** Set when the name looks like a typosquat of a popular package (offline heuristic). */
  suspiciousName?: { similarTo: string };
  /** How the dep relates to the target runtime, when one was declared (absent = compatible). */
  runtimeCompat?: RuntimeCompat;
  verdict: Verdict;
  reason: string;
}

/** One data source Preflight consults, and what it contributed this run — so a scan is
 * transparent about *what it checked*, not just what it found. `ok` = queried successfully;
 * `degraded` = queried but unreachable (results best-effort); `skipped` = not needed this run
 * (no CVEs to prioritize) or not enabled (needs `--latest`/`--health`/a runtime target). */
export interface DataSource {
  /** Provider + what it provides, e.g. "OSV.dev (advisories)", "CISA KEV (exploited)". */
  name: string;
  status: 'ok' | 'degraded' | 'skipped';
  /** One-line result, e.g. "scanned 342 packages → 3 advisories in 2 packages". */
  detail: string;
}

export interface Report {
  ecosystem: Ecosystem;
  path: string;
  total: number;
  findings: Finding[];
  summary: Record<Verdict, number>;
  /** The runtime the scan checked against (this manifest's ecosystem), when one applied. */
  runtimeTarget?: RuntimeTarget;
  /** npm only: whether a lockfile expanded the graph (`false` = direct deps only — warn!). */
  lockfile?: boolean;
  /** Data sources that failed to fetch this run (e.g. "CISA KEV", "FIRST EPSS"). When present,
   * results are best-effort — an unreachable KEV feed means exploited-status is *unknown*, not
   * "none", so a green `fail-level: kev` gate should be read with this caveat. Absent = all OK. */
  degraded?: string[];
  /** Every data source Preflight consulted (or skipped) this run and what it returned — the
   * transparency ledger surfaced in the CLI/Action so "what did this actually check?" is visible. */
  sources?: DataSource[];
}
