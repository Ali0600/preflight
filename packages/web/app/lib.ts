// VERDICT_ORDER comes from the `/types` subpath — a zero-import module — so this stays
// client-bundle-safe (the core barrel would drag node:fs/crypto in via the engine).
import { VERDICT_ORDER } from '@preflight/core/types';
import type { Finding, Report, Verdict } from '@preflight/core';

// Client-safe helpers: types + pure functions only (no engine runtime, so nothing pulls
// node:fs into the browser bundle).

export const SAMPLE_PACKAGE_JSON = `{
  "dependencies": {
    "expo": "56.0.12",
    "react-native": "0.85.3",
    "lodash": "4.17.20",
    "axios": "0.21.1",
    "picocolors": "1.0.0"
  }
}`;

export const VERDICT_META: Record<Verdict, { label: string; icon: string }> = {
  malware: { label: 'Malware', icon: 'ti-biohazard' },
  cve: { label: 'CVE', icon: 'ti-alert-triangle' },
  incompatible: { label: 'Incompatible', icon: 'ti-plug-off' },
  deprecated: { label: 'Deprecated', icon: 'ti-archive' },
  pinned: { label: 'Pinned', icon: 'ti-lock' },
  stale: { label: 'Stale', icon: 'ti-clock' },
  safe: { label: 'Safe', icon: 'ti-circle-check' },
};

/** Problems first: malware, cve, then pinned, stale, safe — the shared worst-first order. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict]);
}

const SEV_RANK = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;

/** Worst CVE severity across the report, for the "Known CVEs" card subtitle. */
export function worstCveSeverity(report: Report): string | undefined {
  let worst: keyof typeof SEV_RANK = 'unknown';
  for (const f of report.findings) {
    for (const v of f.vulns) if (SEV_RANK[v.severity] > SEV_RANK[worst]) worst = v.severity;
  }
  return worst === 'unknown' ? undefined : worst;
}

/** OpenSSF health letter grade from the average scorecard, or null when no health data. */
export function healthGrade(report: Report): string | null {
  const scores = report.findings.map((f) => f.health).filter((h): h is number => h !== undefined);
  if (scores.length === 0) return null;
  const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
  if (avg >= 8) return 'A';
  if (avg >= 6) return 'B';
  if (avg >= 4) return 'C';
  if (avg >= 2) return 'D';
  return 'F';
}

/** A version cell like "0.85.3 → 0.86.0" when a newer release exists, else the resolved version. */
export function versionCell(f: Finding): string {
  if (f.latest && f.version && f.latest !== f.version) return `${f.version} → ${f.latest}`;
  return f.version ?? f.range;
}

/** A short, dynamic insight line for the callout. Malware leads — it's the one verdict that
 * should never read calm (a malware-only report previously showed no risk line at all). */
export function insight(report: Report): string {
  const { summary, total } = report;
  const parts: string[] = [];
  if (summary.malware > 0)
    parts.push(
      `${summary.malware} known-malicious ${summary.malware === 1 ? 'package' : 'packages'} — remove immediately`,
    );
  if (summary.cve > 0)
    parts.push(`${summary.cve} ${summary.cve === 1 ? 'CVE needs' : 'CVEs need'} attention before merging`);
  if (summary.incompatible > 0)
    parts.push(
      `${summary.incompatible} cannot install on ${report.runtimeTarget ? `${report.runtimeTarget.runtime === 'node' ? 'Node' : 'Python'} ${report.runtimeTarget.version}` : 'the target runtime'}`,
    );
  if (summary.deprecated > 0)
    parts.push(
      `${summary.deprecated} deprecated upstream — the maintainer says stop using ${summary.deprecated === 1 ? 'it' : 'them'}`,
    );
  if (summary.pinned > 0)
    parts.push(`${summary.pinned} framework-pinned — bump via the framework's tool, not per-package`);
  parts.push(`${summary.safe} of ${total} independent and safe to auto-update now`);
  return parts.join(' · ') + '.';
}
