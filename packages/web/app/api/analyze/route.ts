import { analyzeContent, setCacheEnabled, type Report } from '@preflight/core';

// The engine touches node:fs/crypto (its disk cache), so this must run on the Node runtime,
// and never be statically cached — each paste is a fresh analysis.
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Serverless filesystems are read-only outside /tmp; skip the on-disk cache here.
setCacheEnabled(false);

export async function POST(request: Request): Promise<Response> {
  try {
    const { filename, content, health } = (await request.json()) as {
      filename?: string;
      content?: string;
      health?: boolean;
    };
    if (!content?.trim()) {
      return Response.json({ error: 'Paste a manifest first.' }, { status: 400 });
    }
    const report: Report = await analyzeContent(filename || 'package.json', content, {
      latest: true,
      health: Boolean(health),
    });
    return Response.json(report);
  } catch (err) {
    // Bad JSON, an unsupported manifest, or an upstream failure — surface the message.
    return Response.json({ error: (err as Error).message }, { status: 400 });
  }
}
