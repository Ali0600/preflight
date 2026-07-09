import { existsSync, readFileSync } from 'node:fs';

import { licenseRisk } from './license';
import { runtimeLabel } from './verdict';
import type { Finding, RuntimeName } from './types';

// A policy turns Preflight's signals into a configurable gate. It's the same engine the CLI
// (`--policy`) and the Action (`policy-file`) share — so "what fails the build" lives in one place.

export interface Policy {
  failOn?: {
    /** Vulnerability threshold: 'cve' (any), 'kev' (confirmed-exploited), 'epss:<0-1>'. Malware always fails. */
    vuln?: string;
    /** Fail if a dependency runs an install script. */
    installScript?: boolean;
    /** Fail if the resolved version is deprecated upstream (npm `deprecated` / PyPI yank).
     * Needs registry data — enabling this turns on the `--latest` fetch, like `license`. */
    deprecated?: boolean;
    /** Fail if a dependency's name looks like a typosquat of a popular package. */
    suspiciousName?: boolean;
    /** Fail on these license ids, or the buckets "copyleft" / "unknown". */
    license?: string[];
    /** Fail if a direct dependency's OpenSSF health score is below this (0–10). */
    minHealth?: number;
    /** Fail on runtime incompatibility: 'incompatible' = the range/locked version cannot
     * install on the target runtime; 'latest-dropped' also fails when the newest release
     * dropped it (the next auto-bump would break). */
    runtime?: 'incompatible' | 'latest-dropped';
  };
  /** Target runtimes the manifest must install on, e.g. { "python": "3.9", "node": "18" }.
   * Shared config-file home for the CLI/Action (flags override). */
  runtimes?: Partial<Record<RuntimeName, string>>;
  /** Adjudicated exceptions. Every allow that fires is ANNOUNCED in the result's
   * `suppressed` list — a silent allow-list becomes invisible risk. Malware is never
   * suppressible. */
  allow?: {
    /** Packages permitted to run install scripts (native binaries: esbuild, sharp, …). */
    installScripts?: string[];
    /** Advisory ids (GHSA-… / CVE-…) accepted as unactionable (e.g. vendored by a
     * framework that hasn't released the fix yet). */
    advisories?: string[];
  };
}

export interface Violation {
  rule: string;
  dep: string;
  detail: string;
}

const SEVERITY_FLOOR: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
/** Unrated advisories rank as low: the lowest floor still catches everything, and higher
 * floors exclude them *explicitly* rather than by a silent hole in the gate. */
const severityRank = (s: string): number => SEVERITY_FLOOR[s] ?? 1;

/** Whether a finding's vulnerabilities meet the threshold. Malware always qualifies; shared with
 * the CLI's --fail-level and the Action's fail-level/policy so every surface means the same thing.
 * Levels: 'cve' (any), 'kev', 'epss:<0-1>', 'severity:<low|medium|high|critical>' (#35).
 * A KEV'd advisory passes ANY threshold — confirmed exploitation beats a severity label. */
export function meetsVulnLevel(f: Finding, level: string): boolean {
  if (f.verdict === 'malware') return true;
  if (f.verdict !== 'cve') return false;
  if (level === 'kev') return f.vulns.some((v) => v.kev);
  if (level.startsWith('epss:')) {
    const t = Number(level.slice(5)) || 0;
    return f.vulns.some((v) => v.kev || (v.epss ?? 0) >= t);
  }
  if (level.startsWith('severity:')) {
    const floor = SEVERITY_FLOOR[level.slice('severity:'.length).toLowerCase()];
    // An unrecognized floor degrades to the STRICTER 'cve' behavior — a typo must
    // never silently weaken the gate.
    if (floor === undefined) return true;
    return f.vulns.some((v) => v.kev || severityRank(v.severity) >= floor);
  }
  return true; // 'cve' (default)
}

function licenseDenied(license: string, deny: string[]): boolean {
  const risk = licenseRisk(license);
  return deny.some((d) => {
    const dl = d.toLowerCase();
    if (dl === 'copyleft' || dl === 'unknown') return risk === dl;
    return license.toLowerCase() === dl;
  });
}

/** Evaluate a policy against findings → violations, whether the gate should fail, and the
 * findings an `allow` rule suppressed (announced, never silent). */
export function evaluatePolicy(
  findings: Finding[],
  policy: Policy,
): { violations: Violation[]; fail: boolean; suppressed: Violation[] } {
  const rules = policy.failOn ?? {};
  const allowScripts = new Set(policy.allow?.installScripts ?? []);
  const allowAdvisories = new Set(policy.allow?.advisories ?? []);
  const violations: Violation[] = [];
  const suppressed: Violation[] = [];
  for (const f of findings) {
    const at = `${f.name}@${f.version ?? f.range}`;
    // Malware fails unconditionally — the documented invariant holds even when the policy
    // configures no `vuln` rule at all, and no `allow` entry is consulted.
    if (f.verdict === 'malware') {
      violations.push({ rule: 'vuln', dep: at, detail: f.reason });
      continue;
    }
    if (rules.vuln && meetsVulnLevel(f, rules.vuln)) {
      const allowed = f.vulns.filter(
        (v) => allowAdvisories.has(v.id) || (v.cve !== undefined && allowAdvisories.has(v.cve)),
      );
      const live = f.vulns.filter((v) => !allowed.includes(v));
      // Re-judge with only the un-allowed advisories: if nothing live meets the bar,
      // the finding is suppressed (and announced), not violated.
      const stillFails =
        live.length > 0 && meetsVulnLevel({ ...f, vulns: live }, rules.vuln);
      if (stillFails) {
        violations.push({ rule: 'vuln', dep: at, detail: f.reason });
      } else {
        suppressed.push({
          rule: 'vuln',
          dep: at,
          detail: `${allowed.map((v) => v.cve ?? v.id).join(', ')} (allow.advisories)`,
        });
      }
    }
    if (rules.installScript && f.installScript) {
      if (allowScripts.has(f.name)) {
        suppressed.push({
          rule: 'install-script',
          dep: at,
          detail: 'runs an install script (allow.installScripts)',
        });
      } else {
        violations.push({ rule: 'install-script', dep: at, detail: 'runs an install script' });
      }
    }
    if (rules.suspiciousName && f.suspiciousName) {
      violations.push({ rule: 'suspicious-name', dep: at, detail: `resembles ${f.suspiciousName.similarTo}` });
    }
    if (rules.deprecated && f.deprecated) {
      violations.push({ rule: 'deprecated', dep: at, detail: f.deprecated });
    }
    if (rules.license && f.license && licenseDenied(f.license, rules.license)) {
      violations.push({ rule: 'license', dep: at, detail: f.license });
    }
    if (
      rules.minHealth !== undefined &&
      f.direct !== false &&
      f.health !== undefined &&
      f.health < rules.minHealth
    ) {
      violations.push({ rule: 'min-health', dep: at, detail: `health ${f.health.toFixed(1)} < ${rules.minHealth}` });
    }
    if (rules.runtime && f.runtimeCompat) {
      const rc = f.runtimeCompat;
      const broken = rc.rangeUnsatisfiable || rc.resolvedIncompatible;
      if (broken) {
        violations.push({ rule: 'runtime', dep: at, detail: f.reason });
      } else if (rules.runtime === 'latest-dropped' && rc.latestIncompatible) {
        violations.push({
          rule: 'runtime',
          dep: at,
          detail: `newest release drops ${runtimeLabel(rc.target)} — the next bump breaks (ignore ${rc.firstIncompatible ?? 'newer versions'}+)`,
        });
      }
    }
  }
  return { violations, fail: violations.length > 0, suppressed };
}

/** Does this policy need latest-version / health / runtime data to be evaluated? (drives fetches) */
export function policyNeeds(policy: Policy): { latest: boolean; health: boolean; runtime: boolean } {
  const r = policy.failOn ?? {};
  return {
    // License AND deprecation data both ride the registry (--latest) fetch.
    latest: Boolean(r.license) || Boolean(r.deprecated),
    health: r.minHealth !== undefined,
    runtime: r.runtime !== undefined,
  };
}

/** Load a JSON policy file. When the caller *explicitly requested* this policy (CLI `--policy`,
 * Action `policy-file`), pass `mustExist` — a missing file then throws instead of silently
 * becoming an empty policy that gates nothing (a typo'd path would otherwise neutralize the
 * whole gate while looking configured). The implicit `preflight.config.json` probe for the
 * `runtimes` key keeps the lenient default. */
export function loadPolicy(path: string, mustExist = false): Policy {
  if (!existsSync(path)) {
    if (mustExist) {
      throw new Error(`Policy file not found: ${path} — the gate would silently not apply.`);
    }
    return {};
  }
  return JSON.parse(readFileSync(path, 'utf8')) as Policy;
}
