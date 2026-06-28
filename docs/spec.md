# Preflight — functional spec

## Inputs
- **npm**: `package.json` (+ `package-lock.json` for resolved versions). Direct deps + devDeps.
- **pip**: `requirements*.txt` (pinned `==` versions feed OSV; ranges are flagged "unpinned").
- *(stage 3)* connect a GitHub repo via OAuth and read manifests from the default branch.

## Output — `Report`
Per dependency (`Finding`): `name`, `range`, resolved `version`, `dev`, `vulns[]` (id, summary,
severity), `lockstep` `{pinned, framework, tool}`, `latest`, `verdict`, `reason`.
`verdict ∈ { safe, pinned, cve, stale }`; `summary` counts each.

## Verdict logic (`verdict.ts`)
Precedence:
1. **cve** — ≥1 OSV advisory for the resolved version. Reason names the worst severity; if the dep
   is also framework-pinned, it appends "fix via <tool>".
2. **pinned** — in the framework-lockstep registry. Reason: "update via <tool>".
3. **stale** — *(TODO)* major(s) behind latest AND last-publish old (registry/deps.dev).
4. **safe** — independent, current, no advisories.

## Framework-lockstep registry (`lockstep.ts`) — the core IP
A data-driven list of `{ framework, tool, exact[], prefixes[] }`. Seeded with **Expo, Angular, Nx**.
**Extending it is the point** — add Next.js, SvelteKit, Remix, Nuxt; pip/gem frameworks (Django,
Rails). Stretch: *infer* lockstep from the lockfile (a transitive dep constrained by a framework
parent's peer range), not just the static list.

## APIs (keyless — verify shapes against the live docs before coding)
- **OSV.dev** — `POST /v1/querybatch` `{queries:[{package:{name,ecosystem},version}]}` → vuln ids;
  then `GET /v1/vulns/{id}` for severity (GHSA `database_specific.severity`). Ecosystems: `npm`, `PyPI`.
  Docs: https://google.github.io/osv.dev/api/
- **deps.dev v3** — `GET /v3/systems/{npm|pypi}/packages/{name}/versions/{ver}` → `relatedProjects`;
  `GET /v3/projects/{key}` → `scorecard.overallScore`. **Confirm system casing + paths.**
  Docs: https://docs.deps.dev/api/v3/
- **npm registry** — `GET registry.npmjs.org/{name}` → `dist-tags.latest`, `time` (last publish).
- **PyPI** — `GET pypi.org/pypi/{name}/json` → `info.version`.
- **endoflife.date** — `GET /api/{product}.json` (runtime/framework EOL).

## Non-functional
- Batch OSV (one `querybatch`); **cache** responses on disk (`.preflight-cache/`, ~24h TTL) to
  respect rate limits and speed re-runs.
- Severity mapping: GHSA `low/moderate/high/critical` → `low/medium/high/critical`.
- CLI/Action exit **non-zero** when any CVE is found (so CI can gate on it).
