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
  newCveCount,
  renderComment,
  renderPolicySection,
  renderRepoIssue,
  shouldFail,
  ISSUE_MARKER,
  MARKER,
  type ManifestReport,
} from './report';

// package.json or requirements*.txt, anywhere in the tree.
const MANIFEST = /(^|\/)(package\.json|requirements[\w.-]*\.txt)$/i;
// A lockfile-only change still moves the installed tree (transitive adds/bumps) —
// it must trigger the scan of its sibling manifest too (dogfood BUG-3/#20).
const LOCKFILE = /(^|\/)package-lock\.json$/i;

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
  const failLevel = core.getInput('fail-level') || 'cve';
  const policyFile = core.getInput('policy-file');
  const policy = policyFile ? loadPolicy(policyFile) : undefined;

  if ((core.getInput('mode') || 'pr') === 'repo') {
    await runRepoScan(octokit, owner, repo, failOnCve, resolveRuntimes(policy));
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
      core.warning(`Skipped ${path}: ${(err as Error).message}`);
    }
  }

  writeSarif(results.map((r) => r.report));
  if (results.length === 0) {
    core.info('No added or bumped dependencies to report.');
    return;
  }

  // Evaluate the policy (if any) against everything this PR introduces — direct AND
  // transitive — so the check that protects main enforces what the CLI enforces locally.
  const policyResult = policy
    ? evaluatePolicy(results.flatMap(introducedFindings), policy)
    : { violations: [], fail: false, suppressed: [] };

  await upsertComment(
    octokit,
    owner,
    repo,
    issue_number,
    renderComment(results) + renderPolicySection(policyResult.violations, policyResult.suppressed),
  );
  core.setOutput('new-cves', newCveCount(results));

  // With a policy, the policy decides; otherwise the fail-level does.
  const gateFail = policy ? policyResult.fail : shouldFail(results, failLevel);
  if (failOnCve && gateFail) {
    const why = policy
      ? `it violates the policy (${policyResult.violations.length} violation(s))`
      : `it meets the fail threshold (fail-level: ${failLevel})`;
    core.setFailed(`Preflight: this PR introduces a dependency that ${why}.`);
  }
}

/** Repo mode (scheduled): scan every committed manifest and open/update a tracking issue. */
async function runRepoScan(
  octokit: Octokit,
  owner: string,
  repo: string,
  failOnCve: boolean,
  runtimes: AnalyzeOptions['runtimes'],
): Promise<void> {
  const paths = findManifests('.');
  core.info(`Scanning ${paths.length} manifest(s).`);
  const reports: Report[] = [];
  for (const path of paths) {
    try {
      reports.push(await analyze(path, { runtimes }));
    } catch (err) {
      core.warning(`Skipped ${path}: ${(err as Error).message}`);
    }
  }

  writeSarif(reports);
  const { body, count } = renderRepoIssue(reports);
  await upsertIssue(octokit, owner, repo, body, count > 0);
  core.setOutput('vuln-count', count);
  if (failOnCve && count > 0) {
    core.setFailed(`Preflight: ${count} known vulnerability finding(s) across the repo's manifests.`);
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
    const lock = await fetchBaseFile(octokit, owner, repo, join(dirname(path), 'package-lock.json'), ref);
    if (lock !== undefined) writeFileSync(join(dir, 'package-lock.json'), lock);
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
