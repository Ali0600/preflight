# Embedding Preflight in another app (e.g. ai-project-dashboard)

Goal: show each project's dependency health *inside* your dashboard, with Preflight as the single
source — so any change to Preflight flows through without copying code. Render the data with **your
own** cards; don't copy Preflight's UI (that's the part that drifts).

Two supported ways. Both work locally and in Docker, neither needs public npm.

---

## Path B — call Preflight as a service (recommended; auto-updates on redeploy)

Preflight's web app exposes a **keyless** `POST /api/scan` — you send the manifest (+ lockfile) you
already have, it returns the full `Report` (incl. the transitive graph). Preflight never reaches for
your repo, so there's no token on its side.

```bash
curl -X POST "$PREFLIGHT_URL/api/scan" -H 'content-type: application/json' \
  -d '{"files":{"package.json":"…","package-lock.json":"…"}}'
# → { total, summary:{cve,malware,…}, findings:[ {name,version,verdict,reason,…} ] }
```

**Every Preflight improvement appears on its next redeploy — zero dashboard changes.**

### Run Preflight as a service
The web app builds to a self-contained server (Next standalone output). Run it however you deploy:

```bash
# Docker (from the repo root) — has a HEALTHCHECK on /api/health
docker build -f packages/web/Dockerfile -t preflight-web .
docker run -p 3000:3000 preflight-web

# or locally without Docker
npm run build -w @preflight/web && npx next start packages/web -p 3000

# or Vercel: import the repo, Root Directory = packages/web
```

No env vars or keys are required (every data source is keyless). Then point the dashboard at it:

```bash
PREFLIGHT_URL=http://localhost:3000          # dev / same-host Docker
# PREFLIGHT_URL=https://preflight.your-host  # deployed
```

Liveness: `GET $PREFLIGHT_URL/api/health` → `{ "ok": true }` (use it to show "Preflight unreachable"
gracefully if it's down). For local dev, a `docker-compose.yml` in the dashboard that runs both
services side by side is the tidiest setup.

### Dashboard side (Next.js App Router + better-sqlite3)
A route that fetches a project's manifests from GitHub (your dashboard already has repo access),
asks Preflight, and caches the `Report` in SQLite for 24h:

```ts
// src/app/api/preflight/route.ts   (in ai-project-dashboard)
import Database from 'better-sqlite3';

const db = new Database('data.db');
db.exec(`CREATE TABLE IF NOT EXISTS preflight (repo TEXT PRIMARY KEY, report TEXT, at INTEGER)`);
const TTL = 24 * 60 * 60 * 1000;

async function ghFile(repo: string, path: string): Promise<string | undefined> {
  const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
    headers: {
      accept: 'application/vnd.github.raw',
      ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
    },
  });
  return r.ok ? r.text() : undefined;
}

export async function GET(req: Request) {
  const repo = new URL(req.url).searchParams.get('repo'); // "owner/name"
  if (!repo) return Response.json({ error: 'repo required' }, { status: 400 });

  const row = db.prepare('SELECT report, at FROM preflight WHERE repo = ?').get(repo) as
    | { report: string; at: number }
    | undefined;
  if (row && Date.now() - row.at < TTL) return Response.json(JSON.parse(row.report));

  const files: Record<string, string> = {};
  for (const p of ['package.json', 'package-lock.json', 'requirements.txt']) {
    const c = await ghFile(repo, p);
    if (c) files[p] = c;
  }
  if (!files['package.json'] && !files['requirements.txt']) return Response.json({ skipped: true });

  const res = await fetch(`${process.env.PREFLIGHT_URL}/api/scan`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ files }),
  });
  const report = await res.json();
  db.prepare('INSERT OR REPLACE INTO preflight (repo, report, at) VALUES (?,?,?)').run(
    repo, JSON.stringify(report), Date.now(),
  );
  return Response.json(report);
}
```

Then a card reads `summary.cve` / `summary.malware` / `findings` and renders it your way (a badge on
each project tile, a panel, whatever fits the kanban). The `Report` shape is in
`packages/core/src/types.ts`.

---

## Path A — run the engine in-process (no second service)

Since your dashboard is also Next.js, you can import `@preflight/core` and call `analyzeFiles()`
directly in the route above (replace the `fetch($PREFLIGHT_URL/api/scan)` call with
`const report = await analyzeFiles(files)`). To get the code in without public npm:

```bash
# in ai-project-dashboard
git submodule add https://github.com/Ali0600/preflight vendor/preflight
npm pkg set dependencies.@preflight/core="file:vendor/preflight/packages/core"
npm install
```
…and add `transpilePackages: ['@preflight/core']` to `next.config.ts` (the engine ships TS source).
**Update Preflight:** `git submodule update --remote vendor/preflight` (optionally a scheduled
Action that bumps the pointer and opens a PR). Works in Docker as long as the build checks out
submodules.

> **GitHub Packages note:** a *registry* dependency would be cleaner than a submodule, but GitHub
> Packages requires the scope to match the owner — `@preflight/core` would have to be renamed to
> `@ali0600/core`. That's a deliberate rename across the monorepo; say the word and I'll do it +
> add an auto-publish workflow. Until then, the submodule is the registry-free equivalent.

---

## Which to use
- Want it **decoupled and auto-updating** with the least coupling → **Path B** (service).
- Want it **all in one Next build**, no second deploy → **Path A** (submodule + `analyzeFiles`).
Both keep Preflight the single source and your dashboard's UI your own.
