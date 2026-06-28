# Preflight

> Pre-flight a dependency **before** you add or auto-update it — known CVEs, health, and whether
> it's actually safe to bump given your framework.

Most tools (Dependabot, Snyk, Socket) analyze the dependencies you *already have*. Preflight
answers the question that bites you *earlier*: **"is this safe to add, and safe to auto-update?"**
Its edge is a **framework-lockstep registry** — it knows that Expo, Angular, Nx (and more) pin a
coordinated set of packages, so it tells you to bump those via the framework's own tool instead of
letting a per-package updater break your build.

## Highlights
- **Supply-chain pre-flight engine** — parses npm/pip manifests, queries the OSV vulnerability
  database and deps.dev (health + OpenSSF Scorecard), and classifies each dependency's
  auto-update safety. Keyless, deterministic, cached.
- **Framework-lockstep detection** — a data-driven registry that flags packages a framework pins
  as a set (Expo `react-native`/`expo-*`, Angular, Nx…), the failure mode generic auto-updaters
  (Dependabot/Renovate) can't see.
- **Three delivery surfaces, one engine** — a CLI, a GitHub Action that gates PRs, and a web
  dashboard, all reusing `@preflight/core`.

## Stages
1. **CLI** (`@preflight/cli`) — `preflight check <manifest>` → a verdict table (`safe` / `pinned` /
   `cve`). **Working today.**
2. **GitHub Action** (`@preflight/action`) — comments on PRs that add or bump a dependency.
3. **Web dashboard** (`@preflight/web`, Next.js) — paste a manifest or connect a repo → the
   dashboard in [docs/dashboard-mockup.html](docs/dashboard-mockup.html). Deploy on Vercel.

## Quickstart
```bash
npm install
npm run check -- path/to/package.json      # or a requirements*.txt
npm test                                    # vitest
```

Example (grocery-helper's Expo app):
```
17 deps · 0 CVE · 9 pinned · 8 safe
 PINNED  react-native@0.85.3   Framework-pinned (Expo) — update via npx expo install
 SAFE    typescript@6.0.3      Independent — safe to auto-update (CI-gated)
```

## How it works
`@preflight/core` is the single engine: `manifest` → `osv` + `lockstep` (+ `registry`/`depsdev`)
→ `verdict` → `Report`. The CLI, Action, and dashboard are thin wrappers over `analyze()`.
See [docs/spec.md](docs/spec.md) for the verdict logic and API details, and
[docs/preflight-checklist.md](docs/preflight-checklist.md) for the broader dependency-hygiene
practices this tool automates.

## Data sources (all free, no API keys)
OSV.dev · deps.dev (v3) · npm registry · PyPI JSON · endoflife.date

## License
MIT (intended).
