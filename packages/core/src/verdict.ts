import type { Finding, Severity, Vuln } from './types';

const RANK: Record<Severity, number> = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };

function worst(vulns: Vuln[]): Severity {
  return vulns.reduce<Severity>((acc, v) => (RANK[v.severity] > RANK[acc] ? v.severity : acc), 'unknown');
}

/** Decide the auto-update verdict for one dependency from its CVEs + lockstep status. */
export function decideVerdict(f: Omit<Finding, 'verdict' | 'reason'>): {
  verdict: Finding['verdict'];
  reason: string;
} {
  if (f.vulns.length > 0) {
    const tail = f.lockstep.pinned
      ? ` · framework-pinned (${f.lockstep.framework}) — fix via ${f.lockstep.tool}`
      : '';
    return { verdict: 'cve', reason: `${f.vulns.length} advisory · ${worst(f.vulns)}${tail}` };
  }
  if (f.lockstep.pinned) {
    return {
      verdict: 'pinned',
      reason: `Framework-pinned (${f.lockstep.framework}) — update via ${f.lockstep.tool}`,
    };
  }
  return { verdict: 'safe', reason: 'Independent — safe to auto-update (CI-gated)' };
}
