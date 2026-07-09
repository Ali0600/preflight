// Shared types for the Preflight engine. The CLI, GitHub Action, and web dashboard
// all consume these — keep this the single source of truth.

export type Ecosystem = 'npm' | 'PyPI';

export type Severity = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export type Verdict = 'malware' | 'cve' | 'incompatible' | 'deprecated' | 'pinned' | 'stale' | 'safe';

/** Worst-first sort rank for verdicts — shared by every surface so tables/lists agree.
 * Lives here (types.ts has zero imports) so the web CLIENT bundle can import it via the
 * `@preflight/core/types` subpath without dragging node:fs/crypto from the engine barrel. */
export const VERDICT_ORDER: Record<Verdict, number> = {
  malware: 0,
  cve: 1,
  incompatible: 2,
  deprecated: 3,
  pinned: 4,
  stale: 5,
  safe: 6,
};

/** Console-style badge label per verdict (CLI + Action). The web picks its own display text. */
export const VERDICT_LABEL: Record<Verdict, string> = {
  malware: 'MALWARE',
  cve: 'CVE',
  incompatible: 'INCOMPAT',
  deprecated: 'DEPRECATED',
  pinned: 'PINNED',
  stale: 'STALE',
  safe: 'SAFE',
};

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
  /** Build/publish attestation (npm Sigstore provenance / PyPI PEP 740), when `--health` is
   * requested. `verified` = deps.dev checked the signature; `sourceRepository` = the repo the
   * artifact provably came from. Absent = none shipped (true of most packages — informational). */
  provenance?: { verified: boolean; sourceRepository?: string };
  /** SPDX-ish license id (e.g. "MIT", "GPL-3.0"), when `--latest` is requested. */
  license?: string;
  /** Upstream deprecation notice for the resolved version (npm `deprecated` message /
   * PyPI fully-yanked release), when `--latest` is requested. Deprecation is the
   * maintainer saying "stop using this" — a pre-flight should repeat it. */
  deprecated?: string;
  /** Set when the name looks like a typosquat of a popular package (offline heuristic).
   * Weekly download counts (when reachable) put numbers behind the hunch: a lookalike nobody
   * installs next to a target everyone installs is the classic typosquat signature. */
  suspiciousName?: { similarTo: string; downloadsPerWeek?: number; targetDownloadsPerWeek?: number };
  /** Weekly downloads (npm downloads API / pypistats.org) for direct deps under `--health`. */
  downloadsPerWeek?: number;
  /** How the dep relates to the target runtime, when one was declared (absent = compatible). */
  runtimeCompat?: RuntimeCompat;
  verdict: Verdict;
  reason: string;
}

/** End-of-life status of the target runtime (endoflife.date) — report-level, not per-dep:
 * an EOL interpreter is a risk of the *project*, not of any one dependency. */
export interface RuntimeEol {
  runtime: RuntimeName;
  /** The release cycle the target maps to, e.g. Node "18", Python "3.9". */
  cycle: string;
  /** ISO date the cycle hits (or hit) end-of-life; absent = no EOL published. */
  eol?: string;
  isEol: boolean;
  /** Days until EOL (negative = past). Absent when no EOL date is published. */
  daysUntilEol?: number;
  /** Newest patch release in the cycle, for context. */
  latest?: string;
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
  /** End-of-life status of that runtime (endoflife.date), when a target was set and its
   * cycle resolved. `isEol` on a green scan is the "you're safe, but on a dead interpreter"
   * heads-up no dependency-level check can give. */
  runtimeEol?: RuntimeEol;
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
