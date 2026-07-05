import {
  meetsVulnLevel,
  runtimeLabel,
  type Report,
  type Verdict,
  type Violation,
} from '@preflight/core';

// Pure presentation/diff logic — no @actions/* imports, so it's unit-testable on its own.

/** Escape a value for a Markdown table cell: a literal `|` (even inside a code span) breaks the
 * table, and a newline breaks the row. Package names/versions come from a manifest we don't
 * control, and advisory text is free-form — defensive, cheap. */
function cell(s: string): string {
  return s.replace(/\r?\n/g, ' ').replace(/\|/g, '\\|');
}

/** A "⛔ Policy violations" markdown section for the PR comment, or '' when there is
 * nothing to report. Suppressions (policy `allow` rules) are announced, never silent. */
export function renderPolicySection(violations: Violation[], suppressed: Violation[] = []): string {
  if (violations.length === 0 && suppressed.length === 0) return '';
  const lines: string[] = [];
  if (violations.length > 0) {
    lines.push('', '### ⛔ Policy violations', '', '| Rule | Package | Detail |', '| --- | --- | --- |');
    for (const v of violations) lines.push(`| \`${cell(v.rule)}\` | \`${cell(v.dep)}\` | ${cell(v.detail)} |`);
  }
  if (suppressed.length > 0) {
    lines.push(
      '',
      `<sub>${suppressed.length} finding(s) suppressed by policy \`allow\` rules: ${suppressed
        .map((s) => `\`${s.dep}\` (${s.rule})`)
        .join(', ')}</sub>`,
    );
  }
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
  /** dep name -> how its *declared* (manifest) entry changed — drives the direct-deps table. */
  changes: Map<string, ChangeStatus>;
  /** `name@version` keys — direct AND transitive — absent from the base tree: everything this
   * PR actually introduces. THIS is what the gate + policy evaluate (the dogfood BUG-3 fix:
   * the old gate looked at `changes` only, so a CVE arriving via the lockfile sailed through). */
  introduced: Set<string>;
}

/** The identity a dependency has in a tree diff: its resolved version when known, else its range. */
export function depKey(d: { name: string; version?: string; range: string }): string {
  return `${d.name}@${d.version ?? d.range}`;
}

/** `name@version` keys in `head` (the scanned findings) that don't exist in the base tree. */
export function introducedKeys(base: { name: string; version?: string; range: string }[], head: Report['findings']): Set<string> {
  const baseKeys = new Set(base.map(depKey));
  return new Set(head.filter((f) => !baseKeys.has(depKey(f))).map(depKey));
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

/** Findings (any depth) this PR introduces, per manifest. */
export function introducedFindings({ report, introduced }: ManifestReport) {
  return report.findings.filter((f) => introduced.has(depKey(f)));
}

/** Introduced deps — direct or transitive — that carry a CVE/malicious advisory. */
export function newCveCount(results: ManifestReport[]): number {
  let n = 0;
  for (const r of results) {
    for (const f of introducedFindings(r)) {
      if (f.verdict === 'cve' || f.verdict === 'malware') n += 1;
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

/** Whether the gate should fail, given the configured level — over everything the PR introduces
 * (direct + transitive), so it matches what the CLI would fail on for the same tree change.
 * The level semantics (malware/cve/kev/epss:x) live in core's `meetsVulnLevel`, shared with the CLI. */
export function shouldFail(results: ManifestReport[], level: string): boolean {
  return results.some((r) => introducedFindings(r).some((f) => meetsVulnLevel(f, level)));
}

/** Transitive CVE carriers that were ALREADY in the base tree — informational, not this PR's doing. */
function preexistingTransitiveCves(results: ManifestReport[]) {
  return results.flatMap((r) =>
    r.report.findings.filter(
      (f) => f.direct === false && f.vulns.length > 0 && !r.introduced.has(depKey(f)),
    ),
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
      lines.push(`| ${EMOJI[f.verdict]} ${LABEL[f.verdict]} | \`${cell(`${f.name}@${f.version ?? f.range}`)}\`${tag} | ${cell(f.reason)} |`);
    }
    lines.push('');
  }

  if (count === 0) lines.push('No known vulnerabilities in the scanned manifests. ✅', '');
  const degraded = [...new Set(reports.flatMap((r) => r.degraded ?? []))];
  if (degraded.length > 0) {
    lines.push(
      `> ⚠️ **Degraded scan** — could not reach ${degraded.join(', ')} this run; results are best-effort (exploited-status may be incomplete).`,
      '',
    );
  }
  lines.push(`_Last scanned ${new Date().toISOString().slice(0, 10)}._`);
  return { body: lines.join('\n'), count };
}

/** Rows shown for introduced-transitive findings before collapsing to "+N more". */
const TRANSITIVE_ROWS = 10;

/** Render the full sticky PR comment (Markdown). Returns just the body. */
export function renderComment(results: ManifestReport[]): string {
  // A manifest is worth a section when its declared deps changed OR the tree changed
  // (a lockfile-only PR has changes.size === 0 but still introduces packages).
  const active = results.filter((r) => r.changes.size > 0 || r.introduced.size > 0);
  const lines = [MARKER, '## ✈️ Preflight — dependency check', ''];

  if (active.length === 0) {
    lines.push('No added or bumped dependencies in this PR. ✅');
    return lines.join('\n');
  }

  for (const r of active) {
    const findings = changedFindings(r);
    const introducedTransitive = introducedFindings(r).filter((f) => f.direct === false);
    const transitiveRisky = introducedTransitive
      .filter((f) => f.vulns.length > 0)
      .sort((a, b) => ORDER[a.verdict] - ORDER[b.verdict]);

    if (findings.length > 0) {
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
          `| ${EMOJI[f.verdict]} ${LABEL[f.verdict]} | \`${cell(`${f.name}@${ver}`)}\` | ${cell(r.changes.get(f.name) ?? '')} | ${cell(note)} |`,
        );
      }
      lines.push('');
    } else {
      // Lockfile-only change: no declared edits, but the installed tree moved.
      lines.push(
        `### \`${r.path}\` — lockfile change · ${r.introduced.size} package(s) introduced or re-resolved`,
        '',
      );
    }

    if (transitiveRisky.length > 0) {
      lines.push(
        `#### 🔎 Transitive findings introduced by this PR — ${transitiveRisky.length}`,
        '',
        '| Verdict | Package | Note |',
        '| --- | --- | --- |',
      );
      for (const f of transitiveRisky.slice(0, TRANSITIVE_ROWS)) {
        lines.push(`| ${EMOJI[f.verdict]} ${LABEL[f.verdict]} | \`${cell(`${f.name}@${f.version ?? f.range}`)}\` | ${cell(f.reason)} |`);
      }
      if (transitiveRisky.length > TRANSITIVE_ROWS) {
        lines.push(`| … | _+${transitiveRisky.length - TRANSITIVE_ROWS} more_ | see the SARIF upload / run the CLI |`);
      }
      lines.push('');
    } else if (findings.length === 0) {
      lines.push('None of the introduced packages carry known CVEs. ✅', '');
    }
  }

  const preexisting = preexistingTransitiveCves(results);
  if (preexisting.length > 0) {
    const names = [...new Set(preexisting.map((f) => `\`${f.name}@${f.version}\``))].slice(0, 8);
    const noun = preexisting.length === 1 ? 'dependency carries' : 'dependencies carry';
    lines.push(
      `🔎 ${preexisting.length} pre-existing transitive ${noun} known CVEs (already in the base tree — not introduced here): ${names.join(', ')}${preexisting.length > names.length ? ', …' : ''}`,
      '',
    );
  }

  const newCves = newCveCount(results);
  lines.push('---');
  lines.push(
    newCves > 0
      ? `❌ **This PR introduces ${newCves} ${newCves === 1 ? 'dependency' : 'dependencies'} with a known CVE or malicious advisory (direct and transitive counted).**`
      : '✅ **No new CVEs introduced (direct and transitive checked).**',
  );
  const degraded = [...new Set(results.flatMap((r) => r.report.degraded ?? []))];
  if (degraded.length > 0) {
    lines.push(
      '',
      `> ⚠️ **Degraded scan** — could not reach ${degraded.join(', ')} this run, so findings are best-effort (e.g. exploited-status may be incomplete). Re-run to retry.`,
    );
  }
  return lines.join('\n');
}
