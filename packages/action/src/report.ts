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
/** Marker on the scheduled-scan tracking issue. */
export const ISSUE_MARKER = '<!-- preflight-scheduled -->';

const EMOJI: Record<Verdict, string> = {
  malware: '☣️',
  cve: '🟥',
  pinned: '🟨',
  stale: '🟪',
  safe: '🟩',
};
const LABEL: Record<Verdict, string> = {
  malware: 'MALWARE',
  cve: 'CVE',
  pinned: 'PINNED',
  stale: 'STALE',
  safe: 'SAFE',
};
const ORDER: Record<Verdict, number> = { malware: 0, cve: 1, pinned: 2, stale: 3, safe: 4 };

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

/** Whether the gate should fail, given the configured level. malware always fails; `cve` fails on
 * any new CVE; `kev` only on confirmed-exploited; `epss:<x>` on probability ≥ x (or KEV). */
export function shouldFail(results: ManifestReport[], level: string): boolean {
  for (const { report, changes } of results) {
    for (const f of report.findings) {
      if (f.direct === false || !changes.has(f.name)) continue;
      if (f.verdict === 'malware') return true;
      if (f.verdict !== 'cve') continue;
      if (level === 'kev') {
        if (f.vulns.some((v) => v.kev)) return true;
      } else if (level.startsWith('epss:')) {
        const t = Number(level.slice(5)) || 0;
        if (f.vulns.some((v) => v.kev || (v.epss ?? 0) >= t)) return true;
      } else {
        return true; // 'cve' (default)
      }
    }
  }
  return false;
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
      const flags = [
        f.installScript ? '⚙ install script' : '',
        f.suspiciousName ? `⚠ resembles \`${f.suspiciousName.similarTo}\`` : '',
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
