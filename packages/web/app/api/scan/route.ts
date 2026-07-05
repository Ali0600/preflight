import { analyzeFiles, GraphTooLargeError, setCacheEnabled, type Report } from '@preflight/core';

// Keyless repo scan: the caller POSTs the manifest (+ lockfile) it already has — Preflight never
// reaches for the repo itself. Runs on the Node runtime (the engine touches node:fs) and is never
// statically cached. Built for the AI-project-dashboard to call per project; see docs/integration.md.
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
// Scanning a large repo's full graph can take a while — give it headroom (Vercel Hobby max is 60s).
export const maxDuration = 60;

setCacheEnabled(false); // serverless FS is read-only outside /tmp

// This endpoint is keyless and public — bound the work: cap the body (a manifest + lockfile is
// well under this), and never echo internal error text to the caller (log it server-side instead).
const MAX_BODY = 8 * 1024 * 1024; // 8 MB
// …and cap the dependency graph: an 8 MB lockfile can still enumerate tens of thousands of
// packages, and each one fans out to OSV/registry/deps.dev. Real projects sit well under this.
const MAX_DEPS = 5000;

export async function POST(request: Request): Promise<Response> {
  const raw = await request.text();
  if (raw.length > MAX_BODY) {
    return Response.json({ error: 'Request body too large.' }, { status: 413 });
  }
  let files: Record<string, string> | undefined;
  try {
    ({ files } = JSON.parse(raw) as { files?: Record<string, string> });
  } catch {
    return Response.json({ error: 'Invalid JSON.' }, { status: 400 });
  }
  if (!files || typeof files !== 'object' || Object.keys(files).length === 0) {
    return Response.json(
      { error: 'POST { files: { "package.json": "…", "package-lock.json": "…" } }' },
      { status: 400 },
    );
  }
  try {
    const report: Report = await analyzeFiles(files, { maxDeps: MAX_DEPS });
    return Response.json(report);
  } catch (err) {
    // A graph over the cap is a limit, not an internal error — its message is self-authored
    // (no path/internal leak), so surface it with a 413 rather than the generic 400.
    if (err instanceof GraphTooLargeError) {
      return Response.json({ error: err.message }, { status: 413 });
    }
    // Unsupported/empty manifest, an unsafe key, or an upstream failure — log the detail, but
    // return a generic message so internal paths/errors don't leak to an unauthenticated caller.
    console.error('preflight /api/scan failed:', err);
    return Response.json(
      { error: 'Could not analyze the manifest — ensure it is a valid package.json (+ lockfile).' },
      { status: 400 },
    );
  }
}
