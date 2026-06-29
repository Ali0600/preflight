import * as core from '@actions/core';
import * as github from '@actions/github';
import { analyze, parseManifestContent, type Dependency } from '@preflight/core';

import {
  diffDeclared,
  newCveCount,
  renderComment,
  shouldFail,
  MARKER,
  type ManifestReport,
} from './report';

// package.json or requirements*.txt, anywhere in the tree.
const MANIFEST = /(^|\/)(package\.json|requirements[\w.-]*\.txt)$/i;

async function run(): Promise<void> {
  const token = core.getInput('github-token');
  const failOnCve = core.getInput('fail-on-cve') !== 'false';
  const failLevel = core.getInput('fail-level') || 'cve';

  const pr = github.context.payload.pull_request;
  if (!pr) {
    core.info('Not a pull_request event — nothing to pre-flight.');
    return;
  }
  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;
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
      const directHead = report.findings.filter((f) => f.direct !== false);
      const changes = diffDeclared(baseDeps, directHead);
      if (changes.size > 0) results.push({ path, report, changes });
    } catch (err) {
      core.warning(`Skipped ${path}: ${(err as Error).message}`);
    }
  }

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

/** Declared deps of the manifest at the PR base, or [] if it's new/unreadable. */
async function fetchBaseDeps(
  octokit: ReturnType<typeof github.getOctokit>,
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

/** Create or update our single sticky comment (identified by MARKER). */
async function upsertComment(
  octokit: ReturnType<typeof github.getOctokit>,
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

run().catch((err) => core.setFailed((err as Error).message));
