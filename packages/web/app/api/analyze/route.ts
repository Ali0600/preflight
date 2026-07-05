import {
  analyzeContent,
  GraphTooLargeError,
  setCacheEnabled,
  type Report,
  type RuntimeName,
} from '@preflight/core';

// The engine touches node:fs/crypto (its disk cache), so this must run on the Node runtime,
// and never be statically cached — each paste is a fresh analysis.
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Serverless filesystems are read-only outside /tmp; skip the on-disk cache here.
setCacheEnabled(false);

// Public + keyless — cap the body and don't echo internal error text to the caller.
const MAX_BODY = 8 * 1024 * 1024; // 8 MB
// Bound the dependency graph too (a paste is direct-only, but keep the guard consistent).
const MAX_DEPS = 5000;

export async function POST(request: Request): Promise<Response> {
  const raw = await request.text();
  if (raw.length > MAX_BODY) {
    return Response.json({ error: 'Request body too large.' }, { status: 413 });
  }
  let body: { filename?: string; content?: string; health?: boolean; runtime?: string };
  try {
    body = JSON.parse(raw);
  } catch {
    return Response.json({ error: 'Invalid JSON.' }, { status: 400 });
  }
  const { filename, content, health, runtime } = body;
  if (!content?.trim()) {
    return Response.json({ error: 'Paste a manifest first.' }, { status: 400 });
  }
  try {
    const name: RuntimeName = /requirements/i.test(filename ?? '') ? 'python' : 'node';
    const version = runtime?.trim();
    const report: Report = await analyzeContent(filename || 'package.json', content, {
      latest: true,
      health: Boolean(health),
      maxDeps: MAX_DEPS,
      runtimes: version
        ? { [name]: { runtime: name, version, source: 'dashboard input', explicit: true } }
        : undefined,
    });
    return Response.json(report);
  } catch (err) {
    // A graph over the cap is a self-authored limit message — surface it as 413, not the generic 400.
    if (err instanceof GraphTooLargeError) {
      return Response.json({ error: err.message }, { status: 413 });
    }
    console.error('preflight /api/analyze failed:', err);
    return Response.json(
      { error: 'Could not analyze the manifest — ensure it is a valid package.json or requirements.txt.' },
      { status: 400 },
    );
  }
}
