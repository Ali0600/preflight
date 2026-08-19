import { analyzeFiles, GraphTooLargeError, setCacheEnabled, type Report } from '@preflight/core';

import { buildFetchPlan, displayPath, parseGitHubUrl, type FetchPlanEntry, type RepoTarget } from './github';

// Scan a PUBLIC GitHub repo from its URL: fetch the manifests off raw.githubusercontent.com, run
// the same engine the paste flow uses, return one report per manifest found. Keyless, like every
// other data source here — and deliberately API-less: the GitHub API's 60/hr unauthenticated limit
// is per-IP, so on a shared deployment every visitor would be spending the same budget. Probing a
// fixed candidate list costs nothing and never rate-limits.
//
// Private repos are out of scope (that's the deferred OAuth item). GitHub returns the same bare
// 404 for "file absent" and "repo private or nonexistent", so the not-found message says both.
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60; // Vercel Hobby cap; the fetch waves are budgeted to fit inside it

setCacheEnabled(false); // serverless FS is read-only outside /tmp

// Public and unauthenticated, so every dimension of the work is bounded.
const MAX_BODY = 10 * 1024; // a URL and a flag — nothing legitimate is bigger
const MAX_DEPS = 5000; // same graph cap as the paste/scan routes
const PER_FILE_MAX = 5 * 1024 * 1024; // a big monorepo lockfile, with headroom
const TOTAL_MAX = 8 * 1024 * 1024; // matches the other routes' body cap
const FETCH_TIMEOUT = 8000; // ms; two sequential waves worst-case 16s of the 60s budget

/** Upstream said something other than 200/404 — rate limit, outage, block. Distinct from absence
 * so the route can fail closed instead of reporting a repo as having no manifests. */
class UpstreamError extends Error {
  constructor(readonly status: number) {
    super(`GitHub responded ${status}`);
  }
}
class TooLargeError extends Error {}

/**
 * Read a response body with a hard byte ceiling, enforced as it streams. `content-length` is a
 * hint we use when present but never rely on — the cap has to hold for a chunked response too.
 */
async function readBounded(res: Response, limit: number, budget: { used: number }): Promise<string> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > limit) throw new TooLargeError();

  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    budget.used += value.length;
    if (size > limit || budget.used > TOTAL_MAX) {
      await reader.cancel();
      throw new TooLargeError();
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Fetch one candidate. `undefined` = not there (404); anything else non-OK throws. */
async function fetchEntry(entry: FetchPlanEntry, budget: { used: number }): Promise<string | undefined> {
  const res = await fetch(entry.url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT),
    // raw.githubusercontent.com answers directly (verified). If it ever starts redirecting, fail
    // loudly rather than follow to a URL this route did not construct.
    redirect: 'error',
    headers: { accept: 'text/plain' },
  });
  if (res.status === 404) return undefined;
  if (!res.ok) throw new UpstreamError(res.status);
  return readBounded(res, PER_FILE_MAX, budget);
}

/** Run the plan: manifests first, then npm lockfiles only if a package.json actually exists. */
async function fetchPlan(target: RepoTarget): Promise<Map<string, string>> {
  const plan = buildFetchPlan(target);
  const budget = { used: 0 };
  const found = new Map<string, string>();

  const manifests = plan.filter((e) => e.kind === 'manifest');
  const results = await Promise.all(manifests.map((e) => fetchEntry(e, budget)));
  manifests.forEach((e, i) => {
    const text = results[i];
    if (text !== undefined) found.set(e.name, text);
  });

  // Wave 2 is worth a round trip only when there's a package.json to expand.
  const pkg = manifests.find((e) => e.name.endsWith('package.json') && found.has(e.name));
  if (pkg) {
    const lockfiles = plan.filter((e) => e.kind === 'lockfile');
    const locks = await Promise.all(lockfiles.map((e) => fetchEntry(e, budget)));
    lockfiles.forEach((e, i) => {
      const text = locks[i];
      if (text !== undefined) found.set(e.name, text);
    });
  }
  return found;
}

export async function POST(request: Request): Promise<Response> {
  const raw = await request.text();
  if (raw.length > MAX_BODY) {
    return Response.json({ error: 'Request body too large.' }, { status: 413 });
  }
  let body: { url?: string; health?: boolean };
  try {
    body = JSON.parse(raw) as { url?: string; health?: boolean };
  } catch {
    return Response.json({ error: 'Invalid JSON.' }, { status: 400 });
  }
  if (!body.url?.trim()) {
    return Response.json({ error: 'Enter a GitHub repo URL first.' }, { status: 400 });
  }

  const parsed = parseGitHubUrl(body.url);
  if (!parsed.ok) return Response.json({ error: parsed.error }, { status: 400 });
  const target = parsed.target;

  let files: Map<string, string>;
  try {
    files = await fetchPlan(target);
  } catch (err) {
    if (err instanceof TooLargeError) {
      return Response.json(
        { error: 'That repo’s manifests exceed the 8 MB scan limit — scan it locally with the CLI instead.' },
        { status: 413 },
      );
    }
    // A timeout or an upstream error is NOT "no manifests found" — reporting it as an empty repo
    // would turn an outage into a clean bill of health. Log the real status, return a generic one.
    console.error('preflight /api/repo fetch failed:', err);
    return Response.json({ error: 'Fetching from GitHub failed — try again shortly.' }, { status: 502 });
  }

  const manifestNames = buildFetchPlan(target)
    .filter((e) => e.kind === 'manifest' && files.has(e.name))
    .map((e) => e.name);

  if (manifestNames.length === 0) {
    const where = `${target.owner}/${target.repo}${target.dir ? `/${target.dir}` : ''}@${target.ref}`;
    return Response.json(
      {
        error: `No supported manifest found at ${where}. GitHub returns the same 404 for a missing file and for a private or nonexistent repo, so check the path — and note that branch names containing "/" aren't supported yet.`,
      },
      { status: 404 },
    );
  }

  // `analyzeFiles` scans the FIRST matching manifest it is handed, so run it once per manifest —
  // a repo with both a package.json and a Gemfile.lock deserves a report for each.
  const lockfilesPresent = Object.fromEntries(
    [...files].filter(([name]) => !manifestNames.includes(name)),
  );
  const reports: Report[] = [];
  try {
    for (const name of manifestNames) {
      const isNpm = name.endsWith('package.json');
      const input: Record<string, string> = { [name]: files.get(name)! };
      if (isNpm) Object.assign(input, lockfilesPresent);

      const report = await analyzeFiles(input, {
        // Parity with /api/analyze: the same Dashboard renders this, and without `latest` the
        // version cells and the stale/deprecated verdicts go dead while the paste flow shows them.
        latest: true,
        health: Boolean(body.health),
        maxDeps: MAX_DEPS,
        // No `runtimes`: the ecosystem isn't known until after the fetch, so a single runtime
        // input would be ambiguous for a repo carrying several manifests. (v2: fetch
        // .nvmrc/.python-version alongside and feed core's detectRuntimes.)
      });
      // The engine reports the throwaway temp path it scanned; show the repo location instead.
      report.path = displayPath(target, name);
      // The ledger's job is "what did this run actually check" — the fetch layer belongs in it.
      report.sources = [
        ...(report.sources ?? []),
        {
          name: 'GitHub (raw.githubusercontent.com)',
          status: 'ok',
          detail: `fetched ${[name, ...(isNpm ? Object.keys(lockfilesPresent) : [])].join(', ')} @ ${target.ref}`,
        },
      ];
      reports.push(report);
    }
  } catch (err) {
    if (err instanceof GraphTooLargeError) {
      return Response.json({ error: err.message }, { status: 413 });
    }
    console.error('preflight /api/repo analysis failed:', err);
    return Response.json(
      { error: 'Could not analyze that repo’s manifests — they may be malformed.' },
      { status: 400 },
    );
  }

  return Response.json({ reports });
}
