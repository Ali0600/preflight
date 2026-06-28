# Dependency pre-flight checklist (reusable across projects)

The hygiene Preflight automates — useful on any repo, with or without the tool.

## 1. Before you add a dependency
- Vet it: `deps.dev`, `Snyk Advisor`, `Socket.dev`, `OpenSSF Scorecard`, `Libraries.io` —
  maintenance recency, maintainer count, known CVEs, transitive weight, license. `bundlephobia` (JS size).
- Fewer, healthier deps. Every dependency is attack surface **and** a future Dependabot PR.
- Know your framework's **lockstep set** (Expo, Rails, Next, Nx, Angular) and let the framework
  own those versions — don't auto-bump them per-package.

## 2. Lock & reproduce
- Commit lockfiles; install with `npm ci` / `uv pip sync` / pinned requirements.

## 3. Gate in CI (don't just alert)
- **CVEs**: `osv-scanner` (all ecosystems), `pip-audit`, `npm audit --audit-level=high`, `Trivy` /
  `Grype` (also containers + IaC).
- **Malicious packages** (typosquats, sketchy install scripts): `Socket.dev` — catches what CVE DBs miss.
- **SAST**: CodeQL (free on GitHub). **Secrets**: `gitleaks`. **SBOM**: `Syft`. **Posture**:
  `OpenSSF Scorecard` action. **Licenses**: `license-checker` / FOSSA.

## 4. Update strategy
- Auto-update only **independently-versioned** deps + security; exclude framework-lockstep sets and
  bump those via the framework's tool. Consider **Renovate** over Dependabot for the config power
  (package rules, grouping, lockfile-only updates).
- Don't trust minor/patch group filters — `0.x` "minor" bumps are routinely breaking.

## 5. Triage by reachability
- Direct vs transitive, **build-time vs runtime**, reachable vs not. A medium CVE in a transitive
  build-time tool (e.g. a bundler's `js-yaml`) is far lower-risk than one in runtime code that
  handles untrusted input. Don't force-fix at the cost of breaking a framework's lockstep.

## 6. Track lifecycles
- `endoflife.date` for runtime/framework EOL; schedule the framework SDK upgrades that clear the
  transitive advisories an auto-updater can't.
