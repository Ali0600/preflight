import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

import { parse as parseYaml } from 'yaml';

import { enumeratePnpmGraph, enumerateYarnGraph } from './lockfiles';
import type { Dependency, Ecosystem, Manifest } from './types';

/** A GitHub Actions workflow file: `*.yml`/`*.yaml` under `.github/workflows/`. Matched on the
 * whole path (not just the basename) so an arbitrary `foo.yml` never parses as a workflow. */
export const WORKFLOW_PATH = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i;

/** Pick the parser for a manifest path, or throw if it isn't one we support. */
function ecosystemFor(path: string): Ecosystem {
  if (WORKFLOW_PATH.test(path)) return 'actions';
  const f = basename(path).toLowerCase();
  if (f === 'package.json') return 'npm';
  if (f.startsWith('requirements') && f.endsWith('.txt')) return 'PyPI';
  throw new Error(
    `Unsupported manifest: ${path} (expected package.json, requirements*.txt, or .github/workflows/*.yml)`,
  );
}

/**
 * Parse manifest *text* (no filesystem access) into a flat dep list — used to read a base-ref
 * manifest fetched over the API (the Action) or pasted into a textarea (the dashboard). npm
 * versions stay unresolved here because the lockfile isn't available; `parseManifest` fills
 * them in from the sibling lockfile when reading off disk.
 */
export function parseManifestContent(filename: string, content: string): Manifest {
  const ecosystem = ecosystemFor(filename);
  const dependencies =
    ecosystem === 'npm' ? parseNpm(content) : ecosystem === 'PyPI' ? parsePip(content) : parseWorkflow(content);
  // Content-only parsing never sees a lockfile; `parseManifest` upgrades this when one exists.
  return { ecosystem, path: filename, dependencies, lockfile: ecosystem === 'npm' ? false : undefined };
}

/** Lockfiles we can expand into the full installed graph, in precedence order (a repo that
 * somehow carries several gets the npm one — it has the richest metadata: dev flags per node
 * + hasInstallScript). */
const NPM_LOCKFILES = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const;

/** Parse an npm (package.json) / pip (requirements.txt) / workflow manifest into a flat dep list. */
export function parseManifest(path: string): Manifest {
  ecosystemFor(path); // reject unsupported types before touching the filesystem
  const manifest = parseManifestContent(path, readFileSync(path, 'utf8'));
  if (manifest.ecosystem === 'npm') {
    const dir = dirname(path);
    const lock = NPM_LOCKFILES.map((f) => join(dir, f)).find(existsSync);
    manifest.lockfile = lock !== undefined;
    if (lock !== undefined) {
      manifest.dependencies = lock.endsWith('package-lock.json')
        ? enumerateNpmGraph(lock, manifest.dependencies)
        : lock.endsWith('pnpm-lock.yaml')
          ? enumeratePnpmGraph(readFileSync(lock, 'utf8'), manifest.dependencies)
          : enumerateYarnGraph(readFileSync(lock, 'utf8'), manifest.dependencies);
    }
  }
  return manifest;
}

/** An exact semver pin (`1.2.3`, `0.85.3-rc.1`) — not a range like `^1` / `~1.2` / `>=1`. */
function exactPin(range: string): string | undefined {
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(range.trim()) ? range.trim() : undefined;
}

function parseNpm(content: string): Dependency[] {
  const pkg = JSON.parse(content) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const deps: Dependency[] = [];
  const add = (obj: Record<string, string> | undefined, dev: boolean) => {
    // An exactly-pinned range *is* the resolved version (used when no lockfile is available,
    // e.g. a manifest pasted into the dashboard); the lockfile overrides this when present.
    for (const [name, range] of Object.entries(obj ?? {}))
      deps.push({ name, range, dev, version: exactPin(range), direct: true });
  };
  add(pkg.dependencies, false);
  add(pkg.devDependencies, true);
  return deps;
}

/**
 * Expand the declared deps with the whole installed graph from the lockfile. The npm
 * `packages` map lists every installed package (direct *and* transitive) with its resolved
 * version — and most exploitable CVEs hide in those indirect deps, so we scan them all.
 * Declared deps are tagged `direct`; everything else in the graph is `direct: false`.
 */
function enumerateNpmGraph(lock: string, declared: Dependency[]): Dependency[] {
  const lj = JSON.parse(readFileSync(lock, 'utf8')) as {
    packages?: Record<string, { version?: string; hasInstallScript?: boolean; dev?: boolean }>;
  };
  const packages = lj.packages ?? {};

  // Pin each declared dep to its installed (top-level) version + install-script flag.
  for (const d of declared) {
    const entry = packages[`node_modules/${d.name}`];
    if (entry?.version) d.version = entry.version;
    if (entry?.hasInstallScript) d.installScript = true;
  }

  const seen = new Set(declared.filter((d) => d.version).map((d) => `${d.name}@${d.version}`));
  const transitive: Dependency[] = [];
  for (const [key, entry] of Object.entries(packages)) {
    const i = key.lastIndexOf('node_modules/');
    if (i === -1 || !entry?.version) continue; // skip the root + workspace package entries
    const name = key.slice(i + 'node_modules/'.length);
    const id = `${name}@${entry.version}`;
    if (!name || seen.has(id)) continue;
    seen.add(id);
    transitive.push({
      name,
      range: '',
      version: entry.version,
      // The lockfile marks packages only reachable via devDependencies (`"dev": true`) —
      // propagate it, or a prod-scope-only policy would misfire on build-tool CVEs (#33).
      dev: entry.dev === true,
      direct: false,
      installScript: entry.hasInstallScript || undefined,
    });
  }
  return [...declared, ...transitive];
}

/** A full commit SHA — the only immutable `uses:` ref (tags and branches can be moved). */
const FULL_SHA = /^[0-9a-f]{40}$/i;

/** A ref that maps to one exact release, e.g. `v4.1.2` / `4.1.2` — usable for advisory
 * matching. Bare major/minor tags (`v4`) float across releases, so they can't be matched. */
function exactActionVersion(ref: string): string | undefined {
  const m = ref.match(/^v?(\d+\.\d+\.\d+)$/);
  return m?.[1];
}

/**
 * Parse a GitHub Actions workflow: every `uses: owner/repo[/path]@ref` across jobs' steps and
 * reusable-workflow jobs becomes a Dependency. Local (`./…`) and `docker://` uses are skipped —
 * they aren't marketplace packages. The OSV package name is `owner/repo` (subpath actions like
 * `github/codeql-action/upload-sarif` are advisories on the repo).
 */
function parseWorkflow(content: string): Dependency[] {
  const doc = parseYaml(content) as {
    jobs?: Record<string, { uses?: string; steps?: { uses?: string }[] }>;
  } | null;
  const uses: string[] = [];
  for (const job of Object.values(doc?.jobs ?? {})) {
    if (job?.uses) uses.push(job.uses); // reusable workflow call
    for (const step of job?.steps ?? []) if (step?.uses) uses.push(step.uses);
  }
  const deps = new Map<string, Dependency>();
  for (const u of uses) {
    if (u.startsWith('./') || u.startsWith('docker://')) continue;
    const at = u.lastIndexOf('@');
    if (at <= 0) continue; // an action without a ref (invalid) — nothing to pin or match
    const [owner, repo] = u.slice(0, at).split('/');
    const ref = u.slice(at + 1);
    if (!owner || !repo) continue;
    const name = `${owner}/${repo}`;
    const key = `${name}@${ref}`;
    if (deps.has(key)) continue;
    deps.set(key, {
      name,
      range: ref,
      version: exactActionVersion(ref),
      dev: false,
      direct: true,
      mutableRef: !FULL_SHA.test(ref),
    });
  }
  return [...deps.values()];
}

function parsePip(content: string): Dependency[] {
  const deps: Dependency[] = [];
  for (const raw of content.split('\n')) {
    const line = raw.split('#')[0]?.trim() ?? '';
    if (!line || line.startsWith('-')) continue; // skip blanks, comments, -r/-e flags
    const m = line.match(/^([A-Za-z0-9._-]+)\s*(.*)$/);
    if (!m) continue;
    const name = m[1] ?? '';
    const range = (m[2] ?? '').trim();
    const pinned = range.match(/==\s*([0-9][^,\s]*)/);
    deps.push({ name, range, dev: false, version: pinned?.[1] });
  }
  return deps;
}
