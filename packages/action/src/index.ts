import { readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import * as core from '@actions/core';
import * as github from '@actions/github';
import { analyze, parseManifestContent, toSarif, type Dependency, type Report } from '@preflight/core';

import {
  diffDeclared,
  newCveCount,
  renderComment,
  renderRepoIssue,
  shouldFail,
  ISSUE_MARKER,
  MARKER,
  type ManifestReport,
} from './report';

// package.json or requirements*.txt, anywhere in the tree.
const MANIFEST = /(^|\/)(package\.json|requirements[\w.-]*\.txt)$/i;

type Octokit = ReturnType<typeof github.getOctokit>;

async function run(): Promise<void> {
  const octokit = github.getOctokit(core.getInput('github-token'));
  const { owner, repo } = github.context.repo;
  const failOnCve = core.getInput('fail-on-cve') !== 'false';
  const failLevel = core.getInput('fail-level') || 'cve';

  if ((core.getInput('mode') || 'pr') === 'repo') {
    await runRepoScan(octokit, owner, repo, failOnCve);
  } else {
    await runPrScan(octokit, owner, repo, failOnCve, failLevel);
  }
}

/** PR mode: diff the changed manifests and post a sticky comment; fail on a newly-introduced risk. */
async function runPrScan(
  octokit: Octokit,
  owner: string,
  repo: string,
  failOnCve: boolean,
  failLevel: string,
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
  const manifests = files.filter((f) => f.status !== 'removed' && MANIFEST.test(f.filename));
  if (manifests.length === 0) {
    core.info('No dependency manifests changed in this PR.');
    return;
  }

  const results: ManifestReport[] = [];
  for (const f of manifests) {
    const path = f.filename;
    try {
      const report = await analyze(path); // head: reads the checked-out file (+ lockfile) and queries OSV
      const baseDeps = await fetchBaseDeps(octokit, owner, repo, path, baseSha);
      // Diff only the declared (direct) deps — the report also contains the transitive graph.
      const changes = diffDeclared(baseDeps, report.findings.filter((d) => d.direct !== false));
      if (changes.size > 0) results.push({ path, report, changes });
    } catch (err) {
      core.warning(`Skipped ${path}: ${(err as Error).message}`);
    }
  }

  writeSarif(results.map((r) => r.report));
  if (results.length === 0) {
    core.info('No added or bumped dependencies to report.');
    return;
  }

  await upsertComment(octokit, owner, repo, issue_number, renderComment(results));
  core.setOutput('new-cves', newCveCount(results));
  if (failOnCve && shouldFail(results, failLevel)) {
    core.setFailed(
      `Preflight: this PR introduces a dependency that meets the fail threshold (fail-level: ${failLevel}).`,
    );
  }
}

/** Repo mode (scheduled): scan every committed manifest and open/update a tracking issue. */
async function runRepoScan(
  octokit: Octokit,
  owner: string,
  repo: string,
  failOnCve: boolean,
): Promise<void> {
  const paths = findManifests('.');
  core.info(`Scanning ${paths.length} manifest(s).`);
  const reports: Report[] = [];
  for (const path of paths) {
    try {
      reports.push(await analyze(path));
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

/** Declared deps of the manifest at the PR base, or [] if it's new/unreadable. */
async function fetchBaseDeps(
  octokit: Octokit,
  owner: string,
  repo: string,
  path: string,
  ref: string | undefined,
): Promise<Dependency[]> {
  if (!ref) return [];
  try {
    const res = await octokit.rest.repos.getContent({ owner, repo, path, ref });
    const data = res.data as { content?: string; encoding?: string };
    if (!data.content) return [];
    const content = Buffer.from(data.content, (data.encoding as BufferEncoding) ?? 'base64').toString(
      'utf8',
    );
    return parseManifestContent(path, content).dependencies;
  } catch {
    return []; // 404 => manifest added in this PR; treat every dep as new
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
