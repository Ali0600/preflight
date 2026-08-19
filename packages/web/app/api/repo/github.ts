// Turn a GitHub URL a human pasted into a bounded list of raw.githubusercontent.com URLs.
//
// SECURITY: the pasted string is NEVER fetched, and never reaches the outbound URL. It is parsed
// into individually-validated segments, and the URL is REBUILT from a hardcoded origin plus those
// segments. That is what keeps a public, unauthenticated endpoint from becoming an SSRF proxy.
// Parsing is deliberately string-only (no `new URL(input)`) so no URL-parser quirk — userinfo,
// backslash normalisation, unicode host mapping — can hand us a host we did not intend.
//
// This module has ZERO imports so it stays trivially unit-testable, mirroring the pure/glue split
// of `packages/action/src/report.ts` vs its `index.ts`.

/** Where to look, after validation. Every field is safe to interpolate into a URL path. */
export interface RepoTarget {
  owner: string;
  repo: string;
  /** Branch, tag, or `HEAD` (which raw.githubusercontent.com resolves to the default branch). */
  ref: string;
  /** Repo-relative directory, `''` for the root. No leading or trailing slash. */
  dir: string;
  /** Set only by a `/blob/` URL: scan exactly this file rather than probing candidates. */
  manifest?: string;
}

export type ParseResult = { ok: true; target: RepoTarget } | { ok: false; error: string };

/** One file to try. `name` doubles as the `analyzeFiles` key, so it must be repo-relative. */
export interface FetchPlanEntry {
  name: string;
  url: string;
  kind: 'manifest' | 'lockfile';
}

const RAW_ORIGIN = 'https://raw.githubusercontent.com';

/** The manifests the engine can scan, in probe order. Fixed on purpose: listing a repo's files
 * would need the GitHub API, whose 60/hr unauthenticated budget is per-IP — i.e. shared by every
 * visitor to the deployed dashboard. A fixed list keeps the feature keyless AND unshared. */
const MANIFEST_NAMES = [
  'package.json',
  'requirements.txt',
  'Gemfile.lock',
  'go.mod',
  'Cargo.lock',
] as const;

/** Fetched beside a package.json so the scan covers the transitive tree, not just direct deps.
 * Core picks the richest one it finds (package-lock first) — we just offer all three. */
const NPM_LOCKFILES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

/** The basename half of core's SCANNABLE_MANIFEST (analyze.ts) — keep the two in step, or a
 * /blob/ URL will accept a file the engine then refuses to scan. */
const MANIFEST_BASENAME = /^(package\.json|requirements[\w.-]*\.txt|Gemfile\.lock|go\.mod|Cargo\.lock)$/i;

// GitHub's own naming rules. Anything outside these charsets cannot express a path separator, a
// percent-escape, a scheme or a control character — which is what makes reconstruction safe.
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;
const REF = /^[A-Za-z0-9._-]{1,128}$/;
const PATH_SEGMENT = /^[A-Za-z0-9._-]{1,255}$/;

const MAX_INPUT = 512;
const MAX_DIR_DEPTH = 10;

/** Deliberately identical for every malformed input: the message is echoed to an anonymous
 * caller, so it must never reflect what they sent or reveal which check tripped. */
const FORM_ERROR =
  'Enter a public GitHub repo as owner/repo, https://github.com/owner/repo, a /tree/<branch>/<dir> URL, or a /blob/<branch>/<manifest> URL.';
const BLOB_ERROR =
  'Point a /blob/ URL at a manifest file: package.json, requirements*.txt, Gemfile.lock, go.mod, or Cargo.lock.';

/** `.` and `..` pass the charset regexes but are path traversal; reject them everywhere. */
function isDotSegment(s: string): boolean {
  return s === '.' || s === '..';
}

export function parseGitHubUrl(input: string): ParseResult {
  if (typeof input !== 'string') return { ok: false, error: FORM_ERROR };
  let rest = input.trim();
  if (!rest || rest.length > MAX_INPUT) return { ok: false, error: FORM_ERROR };

  // Query and fragment are display state, never part of the file path.
  rest = rest.split('?')[0]!.split('#')[0]!;

  // Strip an optional scheme + host. Only github.com is accepted; everything else falls through
  // to the segment checks below, where a host-shaped first segment fails the owner charset.
  const scheme = rest.match(/^(https?):\/\//i);
  if (scheme) rest = rest.slice(scheme[0].length);
  if (/^www\./i.test(rest)) rest = rest.slice(4);
  if (/^github\.com\//i.test(rest)) rest = rest.slice('github.com/'.length);

  // Fast-fail on anything that couldn't be a repo path. Defence-in-depth, NOT the load-bearing
  // filter: probed over 18 hostile inputs (`git@github.com:o/r`, `//evil.com/o/r`,
  // `https://github.com@evil.com/o/r`, backslash paths, embedded whitespace, `file://`,
  // `169.254.169.254`) — every one is already rejected by the segment charsets below, which is
  // where the real guarantee lives. Kept because it fails early and states the intent, and
  // because it still holds if a charset is ever widened.
  if (/[:\\\s]/.test(rest)) return { ok: false, error: FORM_ERROR };

  const segments = rest.split('/').filter((s) => s !== '');
  if (segments.length < 2) return { ok: false, error: FORM_ERROR };

  const owner = segments[0]!;
  const repo = segments[1]!.replace(/\.git$/i, '');
  if (!OWNER.test(owner)) return { ok: false, error: FORM_ERROR };
  if (!REPO.test(repo) || isDotSegment(repo)) return { ok: false, error: FORM_ERROR };

  // owner/repo alone -> probe the default branch at the repo root.
  if (segments.length === 2) return { ok: true, target: { owner, repo, ref: 'HEAD', dir: '' } };

  const kind = segments[2]!.toLowerCase();
  if (kind !== 'tree' && kind !== 'blob') return { ok: false, error: FORM_ERROR };

  const ref = segments[3];
  if (ref === undefined || !REF.test(ref) || isDotSegment(ref)) return { ok: false, error: FORM_ERROR };

  // A branch name containing "/" is genuinely ambiguous in a web URL (is `feat/x` a branch, or
  // branch `feat` plus directory `x`?) and only the API could disambiguate. v1 takes the first
  // segment; the fetch then 404s and the route's message calls this case out by name.
  const pathSegments = segments.slice(4);
  if (pathSegments.length > MAX_DIR_DEPTH) return { ok: false, error: FORM_ERROR };
  for (const s of pathSegments) {
    if (!PATH_SEGMENT.test(s) || isDotSegment(s)) return { ok: false, error: FORM_ERROR };
  }

  if (kind === 'tree') {
    return { ok: true, target: { owner, repo, ref, dir: pathSegments.join('/') } };
  }

  // blob: the last segment must be a manifest, or we would be fetching an arbitrary repo file.
  const manifest = pathSegments[pathSegments.length - 1];
  if (manifest === undefined) return { ok: false, error: FORM_ERROR };
  if (!MANIFEST_BASENAME.test(manifest)) return { ok: false, error: BLOB_ERROR };
  return { ok: true, target: { owner, repo, ref, dir: pathSegments.slice(0, -1).join('/'), manifest } };
}

/** Build the raw URL from validated pieces. `encodeURIComponent` is a no-op on the allowed
 * charsets — it is here so the invariant holds even if a charset is ever widened. */
function rawUrl(target: RepoTarget, repoRelativePath: string): string {
  const parts = [target.owner, target.repo, target.ref, ...repoRelativePath.split('/')];
  return `${RAW_ORIGIN}/${parts.map(encodeURIComponent).join('/')}`;
}

/** Which files to try, at most 8 — manifests first, then the npm lockfiles that expand a
 * package.json into its full transitive graph. */
export function buildFetchPlan(target: RepoTarget): FetchPlanEntry[] {
  const at = (file: string): string => (target.dir ? `${target.dir}/${file}` : file);
  const entry = (file: string, kind: FetchPlanEntry['kind']): FetchPlanEntry => ({
    name: at(file),
    url: rawUrl(target, at(file)),
    kind,
  });

  // A /blob/ URL already named the file — probing the other four would be wasted requests.
  const manifests = target.manifest ? [target.manifest] : [...MANIFEST_NAMES];
  const plan = manifests.map((m) => entry(m, 'manifest'));
  if (manifests.some((m) => m.toLowerCase() === 'package.json')) {
    plan.push(...NPM_LOCKFILES.map((l) => entry(l, 'lockfile')));
  }
  return plan;
}

/** What the dashboard shows instead of the throwaway temp path `analyzeFiles` reports. */
export function displayPath(target: RepoTarget, manifestName: string): string {
  return `${target.owner}/${target.repo}/${manifestName}@${target.ref}`;
}

/** The lockfile names, for the route's wave-2 fetch. */
export const NPM_LOCKFILE_NAMES: readonly string[] = NPM_LOCKFILES;
