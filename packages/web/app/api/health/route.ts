// Liveness probe — the dashboard can check PREFLIGHT_URL is reachable before scanning, and a
// container orchestrator / the Dockerfile HEALTHCHECK can poll it.
export const dynamic = 'force-dynamic';

export function GET(): Response {
  return Response.json({ ok: true, service: 'preflight' });
}
