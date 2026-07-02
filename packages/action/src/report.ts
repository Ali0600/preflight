import {
  meetsVulnLevel,
  runtimeLabel,
  type Report,
  type Verdict,
  type Violation,
} from '@preflight/core';

// Pure presentation/diff logic — no @actions/* imports, so it's unit-testable on its own.

/** A "⛔ Policy violations" markdown section for the PR comment, or '' when there are none. */
export function renderPolicySection(violations: Violation[]): string {
  if (violations.length === 0) return '';
  const lines = ['', '### ⛔ Policy violations', '', '| Rule | Package | Detail |', '| --- | --- | --- |'];
  for (const v of violations) lines.push(`| \`${v.rule}\` | \`${v.dep}\` | ${v.detail} |`);
  return lines.join('\n');
}

export type ChangeStatus = 'added' | 'bumped';

/** Minimal shape both a manifest `Dependency` and a `Finding` satisfy. */
interface Declared {
  name: string;
  range: string;
}

/** Marker so we can find & update our own sticky comment instead of posting a new one each push. */
export const MARKER = '<!-- preflight-action -->';
/** Marker on the scheduled-scan tracking issue. */
export const ISSUE_MARKER = '<!-- preflight-scheduled -->';

const EMOJI: Record<Verdict, string> = {
  malware: '☣️',
  cve: '🟥',
  incompatible: '⛔',
  pinned: '🟨',
  stale: '🟪',
  safe: '🟩',
};
const LABEL: Record<Verdict, string> = {
  malware: 'MALWARE',
  cve: 'CVE',
  incompatible: 'INCOMPAT',
  pinned: 'PINNED',
  stale: 'STALE',
  safe: 'SAFE',
};
const ORDER: Record<Verdict, number> = {
  malware: 0,
  cve: 1,
  incompatible: 2,
  pinned: 3,
  stale: 4,
  safe: 5,
};

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

/** Number of added/bumped direct deps that carry a CVE — i.e. CVEs this PR newly introduces. */
export function newCveCount(results: ManifestReport[]): number {
  let n = 0;
  for (const { report, changes } of results) {
    for (const f of report.findings) {
      if (f.direct !== false && changes.has(f.name) && f.verdict === 'cve') n += 1;
    }
  }
  return n;
}

/** Findings for the direct deps this PR added/bumped, worst verdict first. */
function changedFindings({ report, changes }: ManifestReport) {
  return report.findings
    .filter((f) => f.direct !== false && changes.has(f.name))
    .sort((a, b) => ORDER[a.verdict] - ORDER[b.verdict]);
}

/** Whether the gate should fail, given the configured level — over the deps this PR changed.
 * The level semantics (malware/cve/kev/epss:x) live in core's `meetsVulnLevel`, shared with the CLI. */
export function shouldFail(results: ManifestReport[], level: string): boolean {
  return results.some(({ report, changes }) =>
    report.findings.some(
      (f) => f.direct !== false && changes.has(f.name) && meetsVulnLevel(f, level),
    ),
  );
}

/** Transitive (indirect) deps anywhere in the scanned tree that carry a CVE. */
function transitiveCves(results: ManifestReport[]) {
  return results.flatMap((r) =>
    r.report.findings.filter((f) => f.direct === false && f.vulns.length > 0),
  );
}

/** Render the scheduled-scan tracking issue: every CVE/malware finding across the repo's manifests. */
export function renderRepoIssue(reports: Report[]): { body: string; count: number } {
  const risky = (r: Report) =>
    r.findings.filter((f) => f.verdict === 'malware' || f.verdict === 'cve');
  const lines = [ISSUE_MARKER, '## ✈️ Preflight — scheduled dependency scan', ''];
  let count = 0;

  for (const r of reports) {
    const findings = risky(r).sort((a, b) => ORDER[a.verdict] - ORDER[b.verdict]);
    if (findings.length === 0) continue;
    count += findings.length;
    lines.push(`### \`${r.path}\` — ${findings.length}`, '');
    lines.push('| Verdict | Package | Note |', '| --- | --- | --- |');
    for (const f of findings) {
      const tag = f.direct === false ? ' _(transitive)_' : '';
      lines.push(`| ${EMOJI[f.verdict]} ${LABEL[f.verdict]} | \`${f.name}@${f.version ?? f.range}\`${tag} | ${f.reason} |`);
    }
    lines.push('');
  }

  if (count === 0) lines.push('No known vulnerabilities in the scanned manifests. ✅', '');
  lines.push(`_Last scanned ${new Date().toISOString().slice(0, 10)}._`);
  return { body: lines.join('\n'), count };
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
      const nextBumpBreaks =
        f.runtimeCompat?.latestIncompatible && f.verdict !== 'incompatible'
          ? `⏫ newest release drops ${runtimeLabel(f.runtimeCompat.target)}`
          : '';
      const flags = [
        f.installScript ? '⚙ install script' : '',
        f.suspiciousName ? `⚠ resembles \`${f.suspiciousName.similarTo}\`` : '',
        nextBumpBreaks,
        f.license ? `· ${f.license}` : '',
      ]
        .filter(Boolean)
        .join(' ');
      const note = flags ? `${f.reason} ${flags}` : f.reason;
      lines.push(
        `| ${EMOJI[f.verdict]} ${LABEL[f.verdict]} | \`${f.name}@${ver}\` | ${r.changes.get(f.name)} | ${note} |`,
      );
    }
    lines.push('');
  }

  const transitive = transitiveCves(results);
  if (transitive.length > 0) {
    const names = [...new Set(transitive.map((f) => `\`${f.name}@${f.version}\``))].slice(0, 8);
    lines.push(
      `🔎 ${transitive.length} transitive ${transitive.length === 1 ? 'dependency' : 'dependencies'} in the tree carry known CVEs: ${names.join(', ')}${transitive.length > names.length ? ', …' : ''}`,
      '',
    );
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
