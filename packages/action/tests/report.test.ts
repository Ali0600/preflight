import type { DataSource, Finding, Report, Verdict } from '@preflight/core';
import { describe, expect, it } from 'vitest';

import {
  aggregateSources,
  depKey,
  diffDeclared,
  introducedKeys,
  isAdjudicated,
  matchesAnyGlob,
  newCveCount,
  prGateFails,
  renderComment,
  renderPolicySection,
  renderRepoIssue,
  renderSources,
  shouldFail,
  ISSUE_MARKER,
  MARKER,
  type ManifestReport,
  type SkippedManifest,
} from '../src/report';

/** A cve finding carrying specific advisory ids (for allow.advisories tests). */
function cveWith(name: string, vulns: Finding['vulns']): Finding {
  return { name, range: '^1', version: '1.0.0', dev: false, vulns, lockstep: { pinned: false }, verdict: 'cve', reason: 'cve reason' };
}

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
  const summary: Report['summary'] = { malware: 0, cve: 0, incompatible: 0, deprecated: 0, pinned: 0, stale: 0, safe: 0 };
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
      { name: 'deep', range: '', version: '2.0.0' }, // re-resolved to 2.1.0 in head
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

  it('escapes `|` and newlines in table cells so a crafted advisory cannot break the table (#6)', () => {
    const nasty: Finding = { ...finding('pkg', 'cve'), reason: 'evil | col\ninjection' };
    const r = mr({
      report: report([nasty]),
      changes: new Map([['pkg', 'added']] as const),
      introduced: keysOf(nasty),
    });
    const body = renderComment([r]);
    expect(body).toContain('evil \\| col injection'); // pipe escaped, newline → space
    expect(body).not.toContain('evil | col\ninjection'); // raw form never emitted
  });
});

describe('renderComment — BUG-3/#20: introduced transitive findings are gated, not demoted', () => {
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
    expect(renderPolicySection([], [])).toBe('');
  });

  it('announces allow-rule suppressions even without violations', () => {
    const s = renderPolicySection([], [{ rule: 'install-script', dep: 'esbuild@0.28.1', detail: 'allow.installScripts' }]);
    expect(s).toContain('1 finding(s) suppressed');
    expect(s).toContain('esbuild@0.28.1');
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

  it('surfaces manifests that failed to scan instead of a bare all-clear (#1 audit)', () => {
    const skipped: SkippedManifest[] = [{ path: 'backend/requirements.txt', error: 'OSV querybatch failed: 503' }];
    const { body } = renderRepoIssue([report([finding('fine', 'safe')])], skipped);
    expect(body).toContain('Could not scan');
    expect(body).toContain('backend/requirements.txt');
    expect(body).toContain('OSV querybatch failed: 503');
    expect(body).not.toContain('No known vulnerabilities in the scanned manifests. ✅'); // not a clean all-clear
  });
});

describe('repo mode honors policy allow.advisories (adjudicated = listed, not failing)', () => {
  const allow = new Set(['GHSA-accepted', 'CVE-2099-9999']);

  describe('isAdjudicated', () => {
    it('is true only when EVERY advisory is allow-listed (by id or CVE alias)', () => {
      expect(isAdjudicated(cveWith('a', [{ id: 'GHSA-accepted', summary: 's', severity: 'low' }]), allow)).toBe(true);
      expect(isAdjudicated(cveWith('a', [{ id: 'GHSA-x', summary: 's', severity: 'high', cve: 'CVE-2099-9999' }]), allow)).toBe(true);
    });
    it('is false if any advisory is still live', () => {
      const mixed = cveWith('a', [
        { id: 'GHSA-accepted', summary: 's', severity: 'low' },
        { id: 'GHSA-live', summary: 's', severity: 'high' },
      ]);
      expect(isAdjudicated(mixed, allow)).toBe(false);
    });
    it('never adjudicates malware, even if its id is allow-listed', () => {
      const mal = { ...cveWith('evil', [{ id: 'GHSA-accepted', summary: 'm', severity: 'critical', malicious: true }]), verdict: 'malware' as const };
      expect(isAdjudicated(mal, new Set(['GHSA-accepted']))).toBe(false);
    });
    it('is false with an empty allow-list (the default — no behavior change)', () => {
      expect(isAdjudicated(cveWith('a', [{ id: 'GHSA-accepted', summary: 's', severity: 'low' }]), new Set())).toBe(false);
    });
  });

  it('demotes a fully-accepted finding to the Accepted section and drops it from the count', () => {
    const r = report([cveWith('accepted-pkg', [{ id: 'GHSA-accepted', summary: 's', severity: 'low' }])]);
    const { body, count } = renderRepoIssue([r], [], [], [...allow]);
    expect(count).toBe(0); // does not fail the check
    expect(body).toContain('Accepted by policy'); // …but is announced
    expect(body).toContain('accepted-pkg');
    expect(body).toContain('No unaccepted vulnerabilities — 1 accepted by policy'); // clean line reflects it
  });

  it('keeps a finding with any live advisory red and counted', () => {
    const r = report([
      cveWith('mixed', [
        { id: 'GHSA-accepted', summary: 's', severity: 'low' },
        { id: 'GHSA-live', summary: 's', severity: 'high' },
      ]),
    ]);
    const { body, count } = renderRepoIssue([r], [], [], [...allow]);
    expect(count).toBe(1);
    expect(body).toContain('| 🟥 CVE |');
    expect(body).not.toContain('Accepted by policy');
  });

  it('is a no-op without an allow-list — the finding still counts (default behavior preserved)', () => {
    const r = report([cveWith('accepted-pkg', [{ id: 'GHSA-accepted', summary: 's', severity: 'low' }])]);
    expect(renderRepoIssue([r]).count).toBe(1);
  });
});

describe('matchesAnyGlob (ignore-paths — exclude intentionally-vulnerable fixtures from repo scans)', () => {
  const patterns = ['examples/**', '**/tests/fixtures/**'];

  it('matches paths under an ignored directory at any depth', () => {
    expect(matchesAnyGlob('examples/requirements.txt', patterns)).toBe(true);
    expect(matchesAnyGlob('packages/core/tests/fixtures/npm/package.json', patterns)).toBe(true);
    expect(matchesAnyGlob('tests/fixtures/requirements.txt', patterns)).toBe(true); // `**/` matches zero segments
  });

  it('does NOT match real manifests', () => {
    expect(matchesAnyGlob('package.json', patterns)).toBe(false);
    expect(matchesAnyGlob('packages/web/package.json', patterns)).toBe(false);
    expect(matchesAnyGlob('examples-app/package.json', patterns)).toBe(false); // no prefix bleed
  });

  it('`*` stays within one path segment; `?` is one char', () => {
    expect(matchesAnyGlob('backend/package.json', ['*/package.json'])).toBe(true);
    expect(matchesAnyGlob('a/b/package.json', ['*/package.json'])).toBe(false);
    expect(matchesAnyGlob('app1/package.json', ['app?/package.json'])).toBe(true);
  });

  it('renderRepoIssue announces ignored manifests instead of hiding them', () => {
    const { body } = renderRepoIssue([report([finding('ok', 'safe')])], [], ['examples/requirements.txt']);
    expect(body).toContain('excluded by `ignore-paths`');
    expect(body).toContain('examples/requirements.txt');
  });
});

describe('scan-failure fail-closed (#1 audit — the Action must not go green on a scan it couldn’t run)', () => {
  const clean = mr({
    report: report([finding('ok', 'safe')]),
    changes: new Map([['ok', 'added']] as const),
    introduced: keysOf(finding('ok', 'safe')),
  });
  const skipped: SkippedManifest[] = [{ path: 'package.json', error: 'OSV querybatch failed: 503' }];

  it('prGateFails: a skipped manifest fails the gate even when the scanned results are clean', () => {
    expect(prGateFails([clean], [], { hasPolicy: false, policyFail: false, failLevel: 'cve' })).toBe(false);
    expect(prGateFails([clean], skipped, { hasPolicy: false, policyFail: false, failLevel: 'cve' })).toBe(true);
  });

  it('prGateFails: with no skips, delegates to the policy / fail-level decision', () => {
    expect(prGateFails([clean], [], { hasPolicy: true, policyFail: true, failLevel: 'cve' })).toBe(true);
    expect(prGateFails([clean], [], { hasPolicy: true, policyFail: false, failLevel: 'cve' })).toBe(false);
  });

  it('renderComment: surfaces the un-scanned manifest and a ❌ failing-closed verdict', () => {
    const body = renderComment([clean], skipped);
    expect(body).toContain('Could not scan 1 manifest(s) — failing closed');
    expect(body).toContain('OSV querybatch failed: 503');
    expect(body).toContain('Failing closed');
    expect(body).not.toContain('✅ **No new CVEs'); // the green line must be suppressed
  });

  it('renderComment: an all-skipped PR (no results) never reads as the clean no-op', () => {
    const body = renderComment([], skipped);
    expect(body).not.toContain('No added or bumped dependencies in this PR. ✅');
    expect(body).toContain('Could not scan');
    expect(body).toContain('Failing closed');
  });
});

describe('renderSources — data-source transparency ledger', () => {
  const sources: DataSource[] = [
    { name: 'OSV.dev (advisories)', status: 'ok', detail: 'scanned 3 package version(s) → 0 advisories' },
    { name: 'CISA KEV · FIRST EPSS (exploit prioritization)', status: 'skipped', detail: 'not needed — no CVEs to prioritize' },
    { name: 'npm registry (freshness + license)', status: 'degraded', detail: 'unreachable — latest versions/licenses may be missing' },
  ];

  it('renders a table with a status icon per source', () => {
    const out = renderSources(sources).join('\n');
    expect(out).toContain('📡 Data sources');
    expect(out).toContain('✅ OSV.dev (advisories)');
    expect(out).toContain('➖ CISA KEV'); // skipped
    expect(out).toContain('⚠️ npm registry'); // degraded
    expect(out).toContain('scanned 3 package');
  });

  it('is empty when there are no sources', () => {
    expect(renderSources(undefined)).toEqual([]);
    expect(renderSources([])).toEqual([]);
  });

  it('aggregateSources keeps the worst status a source saw across manifests', () => {
    const a = report([finding('ok', 'safe')]);
    const b = report([finding('ok', 'safe')]);
    a.sources = [{ name: 'CISA KEV (exploited)', status: 'ok', detail: 'ok' }];
    b.sources = [{ name: 'CISA KEV (exploited)', status: 'degraded', detail: 'unreachable' }];
    const merged = aggregateSources([a, b]);
    expect(merged).toHaveLength(1);
    expect(merged[0].status).toBe('degraded'); // degraded outranks ok
  });

  it('aggregateSources drops the combined KEV·EPSS "skipped" row when individual rows exist', () => {
    const withCves = report([finding('bad', 'cve')]);
    const clean = report([finding('ok', 'safe')]);
    withCves.sources = [
      { name: 'CISA KEV (exploited)', status: 'ok', detail: '0 of 3 CVE(s)' },
      { name: 'FIRST EPSS (exploit probability)', status: 'ok', detail: '3 CVE(s) scored' },
    ];
    clean.sources = [
      { name: 'CISA KEV · FIRST EPSS (exploit prioritization)', status: 'skipped', detail: 'not needed' },
    ];
    const merged = aggregateSources([withCves, clean]);
    expect(merged.some((s) => s.name.includes('·'))).toBe(false); // combined row deduped
    expect(merged.some((s) => s.name === 'CISA KEV (exploited)')).toBe(true);
    // …but a run where EVERY manifest was clean keeps the combined row (it's the only signal)
    const allClean = aggregateSources([clean]);
    expect(allClean.some((s) => s.name.includes('·'))).toBe(true);
  });

  it('renderComment surfaces the ledger for a scanned manifest', () => {
    const r = report([finding('ok', 'safe')]);
    r.sources = sources;
    const withSources = mr({
      report: r,
      changes: new Map([['ok', 'added']] as const),
      introduced: keysOf(finding('ok', 'safe')),
    });
    const body = renderComment([withSources]);
    expect(body).toContain('📡 Data sources');
    expect(body).toContain('OSV.dev (advisories)');
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

  it("'cve' fails on an introduced *transitive* CVE too (#20)", () => {
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
