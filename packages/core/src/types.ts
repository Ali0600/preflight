// Shared types for the Preflight engine. The CLI, GitHub Action, and web dashboard
// all consume these — keep this the single source of truth.

export type Ecosystem = 'npm' | 'PyPI';

export type Severity = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export type Verdict = 'malware' | 'cve' | 'pinned' | 'stale' | 'safe';

export interface Dependency {
  name: string;
  /** Version range as declared in the manifest, e.g. "^1.2.0" or ">=2,<3". */
  range: string;
  /** Resolved/installed version, when a lockfile was available (drives OSV queries). */
  version?: string;
  dev: boolean;
  /** Declared in the manifest (`true`) vs pulled in transitively from the lockfile (`false`).
   * Optional so hand-built objects/tests default to direct; the parser always sets it. */
  direct?: boolean;
}

export interface Manifest {
  ecosystem: Ecosystem;
  path: string;
  dependencies: Dependency[];
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
  verdict: Verdict;
  reason: string;
}

export interface Report {
  ecosystem: Ecosystem;
  path: string;
  total: number;
  findings: Finding[];
  summary: Record<Verdict, number>;
}
