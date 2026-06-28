import type { Severity } from './types';

// Compute a qualitative severity from a CVSS v3.x vector string. OSV records carry a
// qualitative GHSA label in `database_specific.severity` for GitHub-sourced advisories
// (the common case for npm/PyPI), but some records only carry a CVSS vector under the
// top-level `severity[]`. This derives the band so those don't fall through to "unknown".
//
// Implements the CVSS v3.1 base-score formula (identical maths to v3.0). v2/v4 vectors
// return undefined — the caller leaves severity as "unknown" rather than guessing.

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 }; // Scope Unchanged
const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 }; // Scope Changed
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

/** CVSS "round up to one decimal place" (ceil at 1 d.p., guarding float error). */
function roundUp(x: number): number {
  return Math.ceil(Number((x * 10).toFixed(4))) / 10;
}

function band(score: number): Severity {
  if (score === 0) return 'unknown'; // CVSS "None" — not a graded risk
  if (score < 4) return 'low';
  if (score < 7) return 'medium';
  if (score < 9) return 'high';
  return 'critical';
}

/** Map a CVSS v3.x vector (e.g. "CVSS:3.1/AV:N/AC:L/...") to a severity band, or undefined. */
export function cvssV3Severity(vector: string): Severity | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const m = new Map(
    vector
      .split('/')
      .map((p) => p.split(':'))
      .filter((kv): kv is [string, string] => kv.length === 2)
      .map(([k, v]) => [k, v] as const),
  );
  const scope = m.get('S');
  const av = AV[m.get('AV') ?? ''];
  const ac = AC[m.get('AC') ?? ''];
  const pr = (scope === 'C' ? PR_C : PR_U)[m.get('PR') ?? ''];
  const ui = UI[m.get('UI') ?? ''];
  const c = CIA[m.get('C') ?? ''];
  const i = CIA[m.get('I') ?? ''];
  const a = CIA[m.get('A') ?? ''];
  if ([av, ac, pr, ui, c, i, a].some((x) => x === undefined)) return undefined;

  const iscBase = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact =
    scope === 'C'
      ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
      : 6.42 * iscBase;
  if (impact <= 0) return band(0);

  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  const raw = scope === 'C' ? 1.08 * (impact + exploitability) : impact + exploitability;
  return band(roundUp(Math.min(raw, 10)));
}
