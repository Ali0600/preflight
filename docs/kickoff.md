# Kickoff — paste this into a fresh Claude Code session opened in this folder

You're continuing **Preflight** (read `CLAUDE.md` first). Stage 1 (the CLI) is a working vertical
slice; build it out across all three stages per `docs/roadmap.md` and `docs/spec.md`.

Steps:
1. Read `CLAUDE.md`, `docs/spec.md`, `docs/roadmap.md`.
2. **Verify the OSV.dev and deps.dev API shapes against their live docs** (Context7 / web) before
   extending the clients — don't trust the current code's assumptions (`depsdev.ts` especially).
3. Finish **Stage 1** (the unchecked items in `roadmap.md`): `--health` + `stale`, a disk cache,
   extend the lockstep registry (Next/SvelteKit/Django/Rails), a `tsup` build, more tests.
4. Then **Stage 2** (GitHub Action), then **Stage 3** (Next.js dashboard matching
   `docs/dashboard-mockup.html`).

Conventions: keep all logic in `@preflight/core`; branch + open a PR and let me merge; author
commits as me only (no Claude co-author trailer); run `npm run lint && npm run typecheck && npm test`
before pushing.

First deliverable: finish Stage 1, open a PR, and show me `preflight check` against two real
manifests — an Expo app and a plain Node or Python project — to confirm the verdicts read right.
