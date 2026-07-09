import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import * as core from '@actions/core';
import * as github from '@actions/github';
import {
  analyze,
  detectRuntimes,
  evaluatePolicy,
  loadPolicy,
  parseManifest,
  parseManifestContent,
  policyNeeds,
  toSarif,
  type AnalyzeOptions,
  type Dependency,
  type Policy,
  type Report,
  type RuntimeName,
} from '@preflight/core';

import {
  diffDeclared,
  introducedFindings,
  introducedKeys,
  matchesAnyGlob,
  newCveCount,
  prGateFails,
  renderComment,
  renderPolicySection,
  renderRepoIssue,
  ISSUE_MARKER,
  MARKER,
  type ManifestReport,
  type SkippedManifest,
} from './report';

// package.json or requirements*.txt, anywhere in the tree.
const MANIFEST = /(^|\/)(package\.json|requirements[\w.-]*\.txt)$/i;
// A lockfile-only change still moves the installed tree (transitive adds/bumps) —
// it must trigger the scan of its sibling manifest too (dogfood BUG-3/#20).
const LOCKFILE = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/i;
const LOCKFILE_NAMES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

type Octokit = ReturnType<typeof github.getOctokit>;

/** Target runtimes: explicit inputs win; otherwise version files at the repo root. */
function resolveRuntimes(policy?: Policy): AnalyzeOptions['runtimes'] {
  const targets = detectRuntimes('.');
  for (const runtime of ['node', 'python'] as RuntimeName[]) {
    const input = core.getInput(`${runtime}-version`);
    if (input) {
      targets[runtime] = { runtime, version: input, source: `${runtime}-version input`, explicit: true };
    } else if (policy?.runtimes?.[runtime]) {
      targets[runtime] = {
        runtime,
        version: policy.runtimes[runtime]!,
        source: 'policy file',
        explicit: true,
      };
    }
  }
  return targets;
}

async function run(): Promise<void> {
  const octokit = github.getOctokit(core.getInput('github-token'));
  const { owner, repo } = github.context.repo;
  const failOnCve = core.getInput('fail-on-cve') !== 'false';
  const failLevelInput = core.getInput('fail-level');
  const failLevel = failLevelInput || 'cve';
  const policyFile = core.getInput('policy-file');
  // mustExist: an explicitly-configured policy file that's missing (e.g. a typo'd path) must
  // fail the run, not silently become an empty policy that gates nothing. Throw → setFailed.
  const policy = policyFile ? loadPolicy(policyFile, true) : undefined;

  // With a policy file the policy is authoritative and fail-level is ignored — say so, or a
  // vuln-less policy silently stops gating CVEs even though fail-level looks set (mirrors the CLI).
  if (policy && failLevelInput) {
    core.warning('Preflight: policy-file governs the gate — the fail-level input is ignored.');
  }

  if ((core.getInput('mode') || 'pr') === 'repo') {
    // Repo mode consults only the policy's `allow.advisories` (adjudicated advisories are listed
    // but don't fail) and `runtimes` — NOT the `failOn` rules, which are PR-introduces-X semantics.
    await runRepoScan(octokit, owner, repo, failOnCve, resolveRuntimes(policy), policy?.allow?.advisories ?? []);
  } else {
    await runPrScan(octokit, owner, repo, failOnCve, failLevel, policy);
  }
}

/** PR mode: diff the changed manifests and post a sticky comment; fail on a newly-introduced risk. */
async function runPrScan(
  octokit: Octokit,
  owner: string,
  repo: string,
  failOnCve: boolean,
  failLevel: string,
  policy?: Policy,
): Promise<void> {
  const pr = github.context.payload.pull_request;
  if (!pr) {
    core.info('Not a pull_request event — nothing to pre-flight.');
    return;
  }
  const issue_number = pr.number;
  const baseSha = (pr.base as { sha: string } | undefined)?.sha;

  const files = await octokit.paginate(octokit.rest.pulls.listFiles, {
    owner,
    repo,
    pull_number: issue_number,
    per_page: 100,
  });
  // Manifests touched directly, plus the sibling manifest of any touched lockfile —
  // a lockfile-only PR (npm audit fix, transitive bump) changes the tree just the same.
  const manifestPaths = new Set<string>();
  for (const f of files) {
    if (f.status === 'removed') continue;
    if (MANIFEST.test(f.filename)) manifestPaths.add(f.filename);
    else if (LOCKFILE.test(f.filename)) manifestPaths.add(join(dirname(f.filename), 'package.json'));
  }
  if (manifestPaths.size === 0) {
    core.info('No dependency manifests or lockfiles changed in this PR.');
    return;
  }

  // A policy's license/min-health rules need the extra registry/health lookups.
  const analyzeOpts: AnalyzeOptions = {
    ...(policy ? policyNeeds(policy) : {}),
    runtimes: resolveRuntimes(policy),
  };
  const results: ManifestReport[] = [];
  const skipped: SkippedManifest[] = [];
  for (const path of manifestPaths) {
    try {
      const report = await analyze(path, analyzeOpts); // head: checked-out file (+ lockfile) → OSV
      const baseTree = await fetchBaseTree(octokit, owner, repo, path, baseSha);
      // Two diffs with different jobs: `changes` = declared (manifest) edits for the comment
      // table; `introduced` = the full-tree name@version diff the gate + policy evaluate.
      const changes = diffDeclared(
        baseTree.filter((d) => d.direct !== false),
        report.findings.filter((d) => d.direct !== false),
      );
      const introduced = introducedKeys(baseTree, report.findings);
      if (changes.size > 0 || introduced.size > 0) results.push({ path, report, changes, introduced });
    } catch (err) {
      // The primary OSV scan throws by design on an upstream/network failure (fail-closed), and a
      // malformed manifest/lockfile throws too. Record it — a manifest we couldn't evaluate must
      // NOT drop into a silent pass (the CLI exits non-zero on the same error). Fail closed below.
      const message = (err as Error).message;
      core.warning(`Could not scan ${path}: ${message}`);
      skipped.push({ path, error: message });
    }
  }

  writeSarif(results.map((r) => r.report));
  // Only truly-nothing-to-do is a clean no-op: no changed manifests AND nothing failed to scan.
  if (results.length === 0 && skipped.length === 0) {
    core.info('No added or bumped dependencies to report.');
    return;
  }

  // Evaluate the policy (if any) against everything this PR introduces — direct AND
  // transitive — so the check that protects main enforces what the CLI enforces locally.
  const policyResult = policy
    ? evaluatePolicy(results.flatMap(introducedFindings), policy, {
        // The runtime target is repo-level, so any report's EOL status speaks for the tree.
        runtimeEol: results.map((r) => r.report.runtimeEol).find(Boolean),
      })
    : { violations: [], fail: false, suppressed: [] };

  await upsertComment(
    octokit,
    owner,
    repo,
    issue_number,
    renderComment(results, skipped) +
      renderPolicySection(policyResult.violations, policyResult.suppressed),
  );
  core.setOutput('new-cves', newCveCount(results));
  core.setOutput('scan-errors', skipped.length);

  // Fail closed on an unscannable manifest; otherwise the policy (if any) or the fail-level decides.
  const gateFail = prGateFails(results, skipped, {
    hasPolicy: Boolean(policy),
    policyFail: policyResult.fail,
    failLevel,
  });
  if (failOnCve && gateFail) {
    const why =
      skipped.length > 0
        ? `could not be fully scanned — ${skipped.length} manifest(s) failed (see the comment). Failing closed`
        : policy
          ? `introduces a dependency that violates the policy (${policyResult.violations.length} violation(s))`
          : `introduces a dependency that meets the fail threshold (fail-level: ${failLevel})`;
    core.setFailed(`Preflight: this PR ${why}.`);
  }
}

/** Repo mode (scheduled): scan every committed manifest and open/update a tracking issue. */
async function runRepoScan(
  octokit: Octokit,
  owner: string,
  repo: string,
  failOnCve: boolean,
  runtimes: AnalyzeOptions['runtimes'],
  allowAdvisories: string[],
): Promise<void> {
  // `ignore-paths`: comma-separated globs for manifests the scheduled scan should not report on
  // (e.g. intentionally-vulnerable demo/fixture files that would drown real findings in noise).
  // Default empty — never silently skip a user's manifest. Every exclusion is announced below.
  const ignoreGlobs = core
    .getInput('ignore-paths')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  const all = findManifests('.');
  const ignored = ignoreGlobs.length ? all.filter((p) => matchesAnyGlob(p, ignoreGlobs)) : [];
  const paths = all.filter((p) => !ignored.includes(p));
  core.info(`Scanning ${paths.length} manifest(s).`);
  if (ignored.length > 0) {
    core.info(`Ignoring ${ignored.length} manifest(s) via ignore-paths: ${ignored.join(', ')}`);
  }
  const reports: Report[] = [];
  const skipped: SkippedManifest[] = [];
  for (const path of paths) {
    try {
      reports.push(await analyze(path, { runtimes }));
    } catch (err) {
      // Don't let a manifest we couldn't scan vanish into a clean "✅ no vulnerabilities" issue —
      // record it so the outage is visible, and fail closed below.
      const message = (err as Error).message;
      core.warning(`Could not scan ${path}: ${message}`);
      skipped.push({ path, error: message });
    }
  }

  writeSarif(reports);
  const { body, count } = renderRepoIssue(reports, skipped, ignored, allowAdvisories);
  await upsertIssue(octokit, owner, repo, body, count > 0 || skipped.length > 0);
  core.setOutput('vuln-count', count);
  core.setOutput('scan-errors', skipped.length);
  if (failOnCve && (count > 0 || skipped.length > 0)) {
    const detail =
      skipped.length > 0
        ? `${count} known vulnerability finding(s), and ${skipped.length} manifest(s) that failed to scan (failing closed)`
        : `${count} known vulnerability finding(s) across the repo's manifests`;
    core.setFailed(`Preflight: ${detail}.`);
  }
}

/** Emit SARIF for the scanned tree so the workflow can upload it to the Security tab. */
function writeSarif(reports: Report[]): void {
  writeFileSync('preflight.sarif', JSON.stringify(toSarif(reports)));
  core.setOutput('sarif-file', 'preflight.sarif');
}

/** Recursively find manifest files, skipping dot-dirs and dependency/build folders. */
function findManifests(root: string): string[] {
  const skip = new Set(['node_modules', 'dist', 'coverage']);
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        if (!e.name.startsWith('.') && !skip.has(e.name)) walk(p);
      } else if (MANIFEST.test(e.name)) {
        out.push(p);
      }
    }
  };
  walk(root);
  return out;
}

/** A file's raw text at a ref. `undefined` on 404 (normal: file doesn't exist at base);
 * other failures warn — a silently-missing base would make everything look "introduced". */
async function fetchBaseFile(
  octokit: Octokit,
  owner: string,
  repo: string,
  path: string,
  ref: string,
): Promise<string | undefined> {
  try {
    // raw media type: response body is the file text (also the only way past the 1 MB
    // base64 cap of the JSON format — real lockfiles routinely exceed it).
    const res = await octokit.rest.repos.getContent({ owner, repo, path, ref, mediaType: { format: 'raw' } });
    return typeof res.data === 'string' ? res.data : undefined;
  } catch (err) {
    if ((err as { status?: number }).status !== 404) {
      core.warning(`Could not read base ${path}@${ref.slice(0, 7)}: ${(err as Error).message}`);
    }
    return undefined;
  }
}

/** The FULL dependency tree at the PR base: manifest + sibling lockfile, parsed offline in a
 * temp dir so the lockfile graph enumerates. [] when the manifest is new in this PR. */
async function fetchBaseTree(
  octokit: Octokit,
  owner: string,
  repo: string,
  path: string,
  ref: string | undefined,
): Promise<Dependency[]> {
  if (!ref) return [];
  const manifest = await fetchBaseFile(octokit, owner, repo, path, ref);
  if (manifest === undefined) return []; // added in this PR → every dep is introduced
  if (!/package\.json$/i.test(path)) return parseManifestContent(path, manifest).dependencies;

  const dir = mkdtempSync(join(tmpdir(), 'preflight-base-'));
  try {
    writeFileSync(join(dir, 'package.json'), manifest);
    // Fetch whichever lockfile the base tree has (npm, pnpm, or yarn) so its graph enumerates.
    for (const name of LOCKFILE_NAMES) {
      const lock = await fetchBaseFile(octokit, owner, repo, join(dirname(path), name), ref);
      if (lock !== undefined) {
        writeFileSync(join(dir, name), lock);
        break;
      }
    }
    return parseManifest(join(dir, 'package.json')).dependencies;
  } catch (err) {
    // e.g. an unparsable base lockfile — fall back to the declared deps so the diff degrades
    // loudly (transitives all count as introduced) instead of silently gating nothing.
    core.warning(`Base tree for ${path} incomplete (${(err as Error).message}) — diffing declared deps only.`);
    return parseManifestContent(path, manifest).dependencies;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Create or update our single sticky PR comment (identified by MARKER). */
async function upsertComment(
  octokit: Octokit,
  owner: string,
  repo: string,
  issue_number: number,
  body: string,
): Promise<void> {
  const comments = await octokit.paginate(octokit.rest.issues.listComments, {
    owner,
    repo,
    issue_number,
    per_page: 100,
  });
  const existing = comments.find((c) => c.body?.includes(MARKER));
  if (existing) {
    await octokit.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body });
  } else {
    await octokit.rest.issues.createComment({ owner, repo, issue_number, body });
  }
}

/** Update the open tracking issue (by ISSUE_MARKER), or open one when there are findings. */
async function upsertIssue(
  octokit: Octokit,
  owner: string,
  repo: string,
  body: string,
  createIfMissing: boolean,
): Promise<void> {
  const issues = await octokit.paginate(octokit.rest.issues.listForRepo, {
    owner,
    repo,
    state: 'open',
    per_page: 100,
  });
  const existing = issues.find((i) => !i.pull_request && i.body?.includes(ISSUE_MARKER));
  if (existing) {
    await octokit.rest.issues.update({ owner, repo, issue_number: existing.number, body });
  } else if (createIfMissing) {
    await octokit.rest.issues.create({
      owner,
      repo,
      title: 'Preflight: dependency vulnerability report',
      body,
    });
  }
}

run().catch((err) => core.setFailed((err as Error).message));
