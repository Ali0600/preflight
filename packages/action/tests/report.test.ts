import type { Finding, Report, Verdict } from '@preflight/core';
import { describe, expect, it } from 'vitest';

import {
  depKey,
  diffDeclared,
  introducedKeys,
  newCveCount,
  renderComment,
  renderPolicySection,
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
  const summary: Report['summary'] = { malware: 0, cve: 0, incompatible: 0, pinned: 0, stale: 0, safe: 0 };
  for (const f of findings) summary[f.verdict] += 1;
  return { ecosystem: 'npm', path: 'package.json', total: findings.length, findings, summary };
}

/** ManifestReport with sane defaults; `introduced` defaults to empty (nothing new). */
function mr(over: Partial<ManifestReport> & { report: Report }): ManifestReport {
  return { path: 'package.json', changes: new Map(), introduced: new Set(), ...over };
}

const keysOf = (...fs: Finding[]) => new Set(fs.map(depKey));

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

describe('introducedKeys (the tree diff the gate runs on)', () => {
  it('flags added and re-resolved packages by name@version; unchanged ones are not introduced', () => {
    const base = [
      { name: 'a', range: '^1.0.0', version: '1.0.0' }, // unchanged
      { name: 'deep', range: '', version: '2.0.0' }, // will be re-resolved to 2.1.0
    ];
    const head = [
      finding('a', 'safe'),
      { ...finding('deep', 'cve'), range: '', version: '2.1.0', direct: false },
      finding('brand-new', 'safe'),
    ];
    const introduced = introducedKeys(base, head);
    expect(introduced.has('a@1.0.0')).toBe(false);
    expect(introduced.has('deep@2.1.0')).toBe(true); // transitive bump counts
    expect(introduced.has('brand-new@1.0.0')).toBe(true);
  });

  it('an empty base tree (manifest added in this PR) introduces everything', () => {
    expect(introducedKeys([], [finding('a', 'safe')]).size).toBe(1);
  });
});

describe('newCveCount', () => {
  it('counts only introduced deps that carry a CVE — at any depth', () => {
    const a = finding('a', 'cve');
    const b = finding('b', 'cve'); // pre-existing → not counted
    const deep = { ...finding('deep', 'cve'), direct: false as const };
    const r = report([a, b, deep, finding('c', 'safe')]);
    const result = mr({
      report: r,
      changes: new Map([['a', 'added']] as const),
      introduced: keysOf(a, deep),
    });
    expect(newCveCount([result])).toBe(2); // direct a + transitive deep; b excluded
  });

  it('counts introduced malware too', () => {
    const mal = { ...finding('evil', 'malware'), direct: false as const };
    expect(newCveCount([mr({ report: report([mal]), introduced: keysOf(mal) })])).toBe(1);
  });
});

describe('renderComment', () => {
  const lp = finding('left-pad', 'cve');
  const ok = finding('ok', 'safe');
  const withCve: ManifestReport = mr({
    report: report([lp, finding('untouched', 'cve'), ok]),
    changes: new Map([
      ['left-pad', 'added'],
      ['ok', 'added'],
    ] as const),
    introduced: keysOf(lp, ok),
  });

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

  it('renders an incompatible row and the next-bump-breaks flag', () => {
    const target = { runtime: 'python' as const, version: '3.9', source: 'input', explicit: true };
    const broken = {
      ...finding('uvicorn', 'incompatible', '>=0.49'),
      runtimeCompat: {
        target,
        rangeUnsatisfiable: true,
        resolvedIncompatible: false,
        latestIncompatible: true,
        maxCompatible: '0.39.0',
        firstIncompatible: '0.40.0',
      },
    };
    const warned = {
      ...finding('fastapi', 'safe'),
      runtimeCompat: {
        target,
        rangeUnsatisfiable: false,
        resolvedIncompatible: false,
        latestIncompatible: true,
        firstIncompatible: '0.129.0',
      },
    };
    const body = renderComment([
      mr({
        path: 'requirements.txt',
        report: report([broken, warned]),
        changes: new Map([
          ['uvicorn', 'added'],
          ['fastapi', 'added'],
        ] as const),
        introduced: keysOf(broken, warned),
      }),
    ]);
    expect(body).toContain('| ⛔ INCOMPAT |');
    expect(body).toContain('⏫ newest release drops Python 3.9'); // on the safe row only
  });

  it('says all-clear when changed deps are clean', () => {
    const clean = mr({
      report: report([ok]),
      changes: new Map([['ok', 'added']] as const),
      introduced: keysOf(ok),
    });
    expect(renderComment([clean])).toContain('No new CVEs introduced');
  });

  it('handles a PR that changed a manifest but no deps', () => {
    const noChanges = mr({ report: report([finding('ok', 'safe')]) });
    expect(renderComment([noChanges])).toContain('No added or bumped dependencies');
  });
});

describe('renderComment — BUG-3: transitive findings the PR introduces are gated, not demoted', () => {
  it('lists an introduced transitive CVE and flips the footer to ❌', () => {
    // The NutriDex shape: the direct dep is clean, but its lockfile entry vendors a CVE.
    const next = finding('next', 'safe', '16.2.10');
    const postcss = { ...finding('postcss', 'cve', '8.4.31'), range: '', direct: false as const };
    const r = mr({
      report: report([next, postcss]),
      changes: new Map([['next', 'added']] as const),
      introduced: keysOf(next, postcss),
    });
    const body = renderComment([r]);
    expect(body).toContain('Transitive findings introduced by this PR — 1');
    expect(body).toContain('postcss@8.4.31');
    expect(body).toContain('❌');
    expect(body).not.toContain('✅ **No new CVEs');
    expect(shouldFail([r], 'cve')).toBe(true); // the gate agrees with the comment
  });

  it('renders a lockfile-only PR (no declared changes) and still gates it', () => {
    const deep = { ...finding('minimist', 'cve'), direct: false as const };
    const r = mr({ report: report([deep]), introduced: keysOf(deep) });
    const body = renderComment([r]);
    expect(body).toContain('lockfile change');
    expect(body).toContain('minimist');
    expect(newCveCount([r])).toBe(1);
  });

  it('keeps pre-existing transitive CVEs informational — with correct grammar', () => {
    const oldVuln = { ...finding('old-vuln', 'cve'), direct: false as const };
    const okDep = finding('ok', 'safe');
    const r = mr({
      report: report([okDep, oldVuln]),
      changes: new Map([['ok', 'added']] as const),
      introduced: keysOf(okDep),
    });
    const body = renderComment([r]);
    expect(body).toContain('1 pre-existing transitive dependency carries known CVEs');
    expect(body).toContain('not introduced here');
    expect(body).toContain('✅ **No new CVEs introduced'); // the PR itself is clean
    expect(shouldFail([r], 'cve')).toBe(false);
  });
});

describe('renderPolicySection', () => {
  it('stays empty with no violations and no suppressions', () => {
    expect(renderPolicySection([])).toBe('');
  });

  it('surfaces allow-list suppressions so exemptions are never silent', () => {
    expect(renderPolicySection([], 2)).toContain('2 would-be violation(s) suppressed');
    const withBoth = renderPolicySection([{ rule: 'vuln', dep: 'x@1', detail: 'd' }], 1);
    expect(withBoth).toContain('Policy violations');
    expect(withBoth).toContain('1 would-be violation(s) suppressed');
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

describe('shouldFail (fail-level, over what the PR introduces)', () => {
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
  const result = (f: Finding): ManifestReport =>
    mr({ report: report([f]), changes: new Map([[f.name, 'added']] as const), introduced: keysOf(f) });

  it("'cve' fails on any new CVE", () => {
    expect(shouldFail([result(cveFinding('a', {}))], 'cve')).toBe(true);
  });

  it("'cve' fails on an introduced *transitive* CVE too (BUG-3)", () => {
    const deep = { ...cveFinding('deep', {}), direct: false as const };
    expect(shouldFail([mr({ report: report([deep]), introduced: keysOf(deep) })], 'cve')).toBe(true);
    // …but not on a pre-existing one the PR didn't touch
    expect(shouldFail([mr({ report: report([deep]) })], 'cve')).toBe(false);
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
