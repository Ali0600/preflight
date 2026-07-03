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

/** Whether a finding's vulnerabilities meet the threshold. Malware always qualifies; shared with
 * the Action's PR gate so "cve/kev/epss:x" means the same thing everywhere. */
export function meetsVulnLevel(f: Finding, level: string): boolean {
  if (f.verdict === 'malware') return true;
  if (f.verdict !== 'cve') return false;
  if (level === 'kev') return f.vulns.some((v) => v.kev);
  if (level.startsWith('epss:')) {
    const t = Number(level.slice(5)) || 0;
    return f.vulns.some((v) => v.kev || (v.epss ?? 0) >= t);
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
    latest: Boolean(r.license),
    health: r.minHealth !== undefined,
    runtime: r.runtime !== undefined,
  };
}

/** Load a JSON policy file, or an empty policy when the file is absent. */
export function loadPolicy(path: string): Policy {
  if (!existsSync(path)) return {};
  return JSON.parse(readFileSync(path, 'utf8')) as Policy;
}
