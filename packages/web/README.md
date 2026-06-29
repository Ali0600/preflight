# @preflight/web

The Preflight dashboard — paste an npm `package.json` or pip `requirements.txt` and get the metric
cards + per-dependency verdicts (`safe` / `pinned` / `cve` / `stale`), dark-mode aware. It's a thin
Next.js (App Router, React 19) wrapper over `@preflight/core`: the `/api/analyze` route handler runs
`analyzeContent()` on the pasted text and returns a `Report`.

## Develop
```bash
npm run dev -w @preflight/web      # http://localhost:3000
```

## Deploy on Vercel
This is a workspace package, so point Vercel at the monorepo and let it install from the root:
- **Root Directory:** `packages/web` (enable *"Include source files outside the Root Directory"*).
- **Install Command:** `npm install` (run at the repo root so the workspace symlink to
  `@preflight/core` resolves).
- **Framework Preset:** Next.js (build `next build`, output auto-detected).

No environment variables or API keys are required — every data source (OSV, deps.dev, npm, PyPI) is
keyless. The `/api/analyze` route runs on the Node.js runtime and disables the on-disk cache, since
serverless filesystems are read-only.

## Deferred
Connecting a GitHub repo via OAuth (read manifests from the default branch) is specced but not built
— the paste flow is the MVP.
