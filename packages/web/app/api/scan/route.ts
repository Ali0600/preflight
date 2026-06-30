import { analyzeFiles, setCacheEnabled, type Report } from '@preflight/core';

// Keyless repo scan: the caller POSTs the manifest (+ lockfile) it already has — Preflight never
// reaches for the repo itself. Runs on the Node runtime (the engine touches node:fs) and is never
// statically cached. Built for the AI-project-dashboard to call per project; see docs/integration.md.
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
// Scanning a large repo's full graph can take a while — give it headroom (Vercel Hobby max is 60s).
export const maxDuration = 60;

setCacheEnabled(false); // serverless FS is read-only outside /tmp

export async function POST(request: Request): Promise<Response> {
  try {
    const { files } = (await request.json()) as { files?: Record<string, string> };
    if (!files || typeof files !== 'object' || Object.keys(files).length === 0) {
      return Response.json(
        { error: 'POST { files: { "package.json": "…", "package-lock.json": "…" } }' },
        { status: 400 },
      );
    }
    const report: Report = await analyzeFiles(files);
    return Response.json(report);
  } catch (err) {
    // unsupported/empty manifest, bad JSON, or an upstream failure
    return Response.json({ error: (err as Error).message }, { status: 400 });
  }
}
