import type { Report, Verdict } from '@preflight/core';

// Pure presentation/diff logic — no @actions/* imports, so it's unit-testable on its own.

export type ChangeStatus = 'added' | 'bumped';

/** Minimal shape both a manifest `Dependency` and a `Finding` satisfy. */
interface Declared {
  name: string;
  range: string;
}

/** Marker so we can find & update our own sticky comment instead of posting a new one each push. */
export const MARKER = '<!-- preflight-action -->';

const EMOJI: Record<Verdict, string> = { cve: '🟥', pinned: '🟨', stale: '🟪', safe: '🟩' };
const LABEL: Record<Verdict, string> = { cve: 'CVE', pinned: 'PINNED', stale: 'STALE', safe: 'SAFE' };

export interface ManifestReport {
  path: string;
  report: Report;
  /** dep name -> how it changed in this PR (only added/bumped deps are flagged). */
  changes: Map<string, ChangeStatus>;
}

/** Declared-dependency diff between a base and head manifest (by name + range). */
export function diffDeclared(base: Declared[], head: Declared[]): Map<string, ChangeStatus> {
  const baseRange = new Map(base.map((d) => [d.name, d.range]));
  const changes = new Map<string, ChangeStatus>();
  for (const d of head) {
    if (!baseRange.has(d.name)) changes.set(d.name, 'added');
    else if (baseRange.get(d.name) !== d.range) changes.set(d.name, 'bumped');
  }
  return changes;
}

/** Number of added/bumped deps that carry a CVE — i.e. CVEs this PR newly introduces. */
export function newCveCount(results: ManifestReport[]): number {
  let n = 0;
  for (const { report, changes } of results) {
    for (const f of report.findings) {
      if (changes.has(f.name) && f.verdict === 'cve') n += 1;
    }
  }
  return n;
}

/** Findings for the deps this PR added/bumped, worst verdict first. */
function changedFindings({ report, changes }: ManifestReport) {
  const order: Record<Verdict, number> = { cve: 0, pinned: 1, stale: 2, safe: 3 };
  return report.findings
    .filter((f) => changes.has(f.name))
    .sort((a, b) => order[a.verdict] - order[b.verdict]);
}

/** Render the full sticky PR comment (Markdown). Returns just the body. */
export function renderComment(results: ManifestReport[]): string {
  const withChanges = results.filter((r) => r.changes.size > 0);
  const lines = [MARKER, '## ✈️ Preflight — dependency check', ''];

  if (withChanges.length === 0) {
    lines.push('No added or bumped dependencies in this PR. ✅');
    return lines.join('\n');
  }

  for (const r of withChanges) {
    const findings = changedFindings(r);
    const cves = findings.filter((f) => f.verdict === 'cve').length;
    const summary = cves > 0 ? ` · 🟥 ${cves} CVE` : '';
    lines.push(`### \`${r.path}\` — ${findings.length} added/bumped${summary}`, '');
    lines.push('| Verdict | Package | Change | Note |', '| --- | --- | --- | --- |');
    for (const f of findings) {
      const ver = f.version ?? f.range;
      lines.push(
        `| ${EMOJI[f.verdict]} ${LABEL[f.verdict]} | \`${f.name}@${ver}\` | ${r.changes.get(f.name)} | ${f.reason} |`,
      );
    }
    lines.push('');
  }

  const newCves = newCveCount(results);
  lines.push('---');
  lines.push(
    newCves > 0
      ? `❌ **This PR introduces ${newCves} ${newCves === 1 ? 'dependency' : 'dependencies'} with a known CVE.**`
      : '✅ **No new CVEs introduced.**',
  );
  return lines.join('\n');
}
