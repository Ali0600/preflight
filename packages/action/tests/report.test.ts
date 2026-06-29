import type { Finding, Report, Verdict } from '@preflight/core';
import { describe, expect, it } from 'vitest';

import {
  diffDeclared,
  newCveCount,
  renderComment,
  renderRepoIssue,
  shouldFail,
  ISSUE_MARKER,
  MARKER,
  type ManifestReport,
} from '../src/report';

function finding(name: string, verdict: Verdict, range = '^1.0.0'): Finding {
  return {
    name,
    range,
    version: range.replace('^', ''),
    dev: false,
    vulns: verdict === 'cve' ? [{ id: 'GHSA-x', summary: 's', severity: 'high' }] : [],
    lockstep: { pinned: verdict === 'pinned', framework: 'Expo', tool: 'npx expo install' },
    verdict,
    reason: `${verdict} reason`,
  };
}

function report(findings: Finding[]): Report {
  const summary: Report['summary'] = { malware: 0, cve: 0, pinned: 0, stale: 0, safe: 0 };
  for (const f of findings) summary[f.verdict] += 1;
  return { ecosystem: 'npm', path: 'package.json', total: findings.length, findings, summary };
}

describe('diffDeclared', () => {
  it('marks added and bumped deps, ignores unchanged', () => {
    const base = [{ name: 'a', range: '^1' }];
    const head = [
      { name: 'a', range: '^2' }, // bumped
      { name: 'b', range: '^1' }, // added
    ];
    const changes = diffDeclared(base, head);
    expect(changes.get('a')).toBe('bumped');
    expect(changes.get('b')).toBe('added');
  });

  it('treats every dep as added when there is no base manifest', () => {
    const changes = diffDeclared([], [{ name: 'a', range: '^1' }]);
    expect(changes.get('a')).toBe('added');
  });
});

describe('newCveCount', () => {
  it('counts only added/bumped deps that carry a CVE', () => {
    const r = report([finding('a', 'cve'), finding('b', 'cve'), finding('c', 'safe')]);
    const changes = new Map([
      ['a', 'added'],
      ['c', 'added'],
    ] as const);
    // `b` has a CVE but isn't part of this PR's changes → not counted.
    expect(newCveCount([{ path: 'package.json', report: r, changes }])).toBe(1);
  });
});

describe('renderComment', () => {
  const withCve: ManifestReport = {
    path: 'package.json',
    report: report([finding('left-pad', 'cve'), finding('untouched', 'cve'), finding('ok', 'safe')]),
    changes: new Map([
      ['left-pad', 'added'],
      ['ok', 'added'],
    ] as const),
  };

  it('includes the marker and only the changed deps', () => {
    const body = renderComment([withCve]);
    expect(body).toContain(MARKER);
    expect(body).toContain('left-pad');
    expect(body).toContain('| 🟥 CVE |');
    expect(body).not.toContain('untouched'); // changed-deps only
  });

  it('flags introduced CVEs in the footer', () => {
    expect(renderComment([withCve])).toContain('introduces 1 dependency with a known CVE');
  });

  it('says all-clear when changed deps are clean', () => {
    const clean: ManifestReport = {
      path: 'package.json',
      report: report([finding('ok', 'safe')]),
      changes: new Map([['ok', 'added']] as const),
    };
    expect(renderComment([clean])).toContain('No new CVEs introduced');
  });

  it('handles a PR that changed a manifest but no deps', () => {
    const noChanges: ManifestReport = {
      path: 'package.json',
      report: report([finding('ok', 'safe')]),
      changes: new Map(),
    };
    expect(renderComment([noChanges])).toContain('No added or bumped dependencies');
  });
});

describe('renderRepoIssue (scheduled scan)', () => {
  it('lists only cve/malware findings, tags transitive, and counts them', () => {
    const r = report([
      finding('direct-cve', 'cve'),
      { ...finding('deep-cve', 'cve'), direct: false },
      finding('fine', 'safe'),
    ]);
    const { body, count } = renderRepoIssue([r]);
    expect(count).toBe(2);
    expect(body).toContain(ISSUE_MARKER);
    expect(body).toContain('direct-cve');
    expect(body).toContain('_(transitive)_'); // deep-cve flagged transitive
    expect(body).not.toContain('| 🟩 SAFE |'); // safe deps omitted
  });

  it('reports all-clear when nothing is vulnerable', () => {
    const { body, count } = renderRepoIssue([report([finding('fine', 'safe')])]);
    expect(count).toBe(0);
    expect(body).toContain('No known vulnerabilities');
  });
});

describe('shouldFail (fail-level)', () => {
  const cveFinding = (name: string, vuln: Partial<Finding['vulns'][number]>): Finding => ({
    name,
    range: '^1',
    version: '1.0.0',
    dev: false,
    vulns: [{ id: 'CVE-x', summary: 's', severity: 'high', cve: 'CVE-x', ...vuln }],
    lockstep: { pinned: false },
    verdict: 'cve',
    reason: 'cve',
  });
  const result = (f: Finding): ManifestReport => ({
    path: 'package.json',
    report: report([f]),
    changes: new Map([[f.name, 'added']] as const),
  });

  it("'cve' fails on any new CVE", () => {
    expect(shouldFail([result(cveFinding('a', {}))], 'cve')).toBe(true);
  });

  it("'kev' fails only on a confirmed-exploited CVE", () => {
    expect(shouldFail([result(cveFinding('a', { epss: 0.9 }))], 'kev')).toBe(false);
    expect(shouldFail([result(cveFinding('a', { kev: true }))], 'kev')).toBe(true);
  });

  it("'epss:<x>' fails above the probability threshold (or on KEV)", () => {
    expect(shouldFail([result(cveFinding('a', { epss: 0.2 }))], 'epss:0.5')).toBe(false);
    expect(shouldFail([result(cveFinding('a', { epss: 0.8 }))], 'epss:0.5')).toBe(true);
  });

  it('malware always fails regardless of level', () => {
    const mal = { ...cveFinding('a', { malicious: true }), verdict: 'malware' as const };
    expect(shouldFail([result(mal)], 'kev')).toBe(true);
  });
});
