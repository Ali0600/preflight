# Rolling Preflight out to your other repos

`scripts/fleet-scan.mts` (`npm run scan:repos`) is the **read-only triage** — it tells you which
repos have findings without touching anything. This doc is the **ongoing protection** step: adding
the Action to the repos worth gating. Because this repo is public, other repos reference the Action
directly — **no Marketplace publish needed**.

## 1. Gate pull requests (the common case)
Add `.github/workflows/preflight.yml` to a target repo:

```yaml
name: Preflight
on: [pull_request]
permissions:
  contents: read
  pull-requests: write     # post the sticky comment
  security-events: write   # upload SARIF to the Security tab (optional)
jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ali0600/preflight/packages/action@main
        # with:
        #   fail-level: kev          # cve (default) | kev | epss:0.5
        #   policy-file: preflight.config.json
```

On every PR that adds/bumps a dependency it posts a verdict comment and fails the check per
`fail-level` (or a `preflight.config.json` policy, if you set `policy-file`).

## 2. Scheduled full-repo scan → a tracking issue
For repos where you want a standing report (not just PR-time), add a second workflow:

```yaml
name: Preflight scan
on:
  schedule: [{ cron: '0 6 * * 1' }]   # Mondays 06:00 UTC
  workflow_dispatch:
permissions: { contents: read, issues: write, security-events: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ali0600/preflight/packages/action@main
        with:
          mode: repo   # scan every committed manifest; open/update one tracking issue
```

## 3. Doing it across many repos
- **Pick from the sweep:** run `npm run scan:repos` and add the workflow to the repos it flags first
  (e.g. `productivity-app`, `fitness-app`).
- **Scripted add (optional):** for each repo, commit the workflow on a branch and open a PR via `gh`:
  ```bash
  gh api -X PUT repos/<owner>/<repo>/contents/.github/workflows/preflight.yml \
    -f message="ci: add Preflight" -f content="$(base64 < preflight.yml)" -f branch=add-preflight
  ```
  (Writes to each repo, so do it deliberately — the read-only sweep doesn't.)

## Stability note
`@main` always tracks the latest. For reproducible CI, **pin to a tag or commit SHA**
(`packages/action@v0.3.0`) once you cut releases, and bump deliberately — the committed
`dist/index.js` is what runs.
