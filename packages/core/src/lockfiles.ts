import { parse } from 'yaml';

import type { Dependency } from './types';

// pnpm-lock.yaml + yarn.lock parsers — same job as the npm branch in manifest.ts: expand the
// declared deps with the whole installed graph, tagging declared entries `direct` and everything
// else `direct: false`. Without these, a pnpm/yarn repo silently got a declared-deps-only scan
// while *looking* fully scanned (the fleet sweep hit exactly that).
//
// Scope notes (deliberate, keep honest):
// - `dev` on TRANSITIVE deps: npm's lockfile marks dev-only reachability per node; pnpm/yarn
//   would need a graph walk to reconstruct it. We tag transitives `dev: false` (treated as prod)
//   — conservative: a scope-filtering consumer scans MORE, never less. Direct deps keep the real
//   flag from package.json.
// - `installScript`: only pnpm v5/v6 expose `requiresBuild` per package; yarn exposes nothing.
//   We propagate it where it exists and never fabricate it.

/** The union of both graphs' shape: resolved name@version pairs + per-spec resolution. */
interface LockGraph {
  /** Every installed `name@version` in the lockfile. */
  all: { name: string; version: string; installScript?: boolean }[];
  /** `name@range` (as declared) -> resolved version, for pinning direct deps. */
  bySpec: Map<string, string>;
}

function assemble(graph: LockGraph, declared: Dependency[]): Dependency[] {
  for (const d of declared) {
    const resolved =
      graph.bySpec.get(`${d.name}@${d.range}`) ??
      // Fall back to any resolution of the name (e.g. the range text drifted from the lock).
      graph.all.find((p) => p.name === d.name)?.version;
    if (resolved) d.version = resolved;
    const entry = graph.all.find((p) => p.name === d.name && p.version === d.version);
    if (entry?.installScript) d.installScript = true;
  }
  const seen = new Set(declared.filter((d) => d.version).map((d) => `${d.name}@${d.version}`));
  const out = [...declared];
  for (const p of graph.all) {
    const id = `${p.name}@${p.version}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      name: p.name,
      range: '',
      version: p.version,
      dev: false, // see scope note above — reconstructing dev-only reachability needs a walk
      direct: false,
      installScript: p.installScript || undefined,
    });
  }
  return out;
}

/** `lodash@4.17.21`, `/lodash@4.17.21`, `/@babel/core/7.24.0`, `foo@1.0.0(react@18.2.0)` →
 * { name, version }. Returns undefined for keys that aren't package entries. */
function parsePnpmKey(rawKey: string): { name: string; version: string } | undefined {
  let key = rawKey.startsWith('/') ? rawKey.slice(1) : rawKey;
  const paren = key.indexOf('(');
  if (paren !== -1) key = key.slice(0, paren); // strip peer-dep suffix
  const at = key.lastIndexOf('@');
  if (at > 0) {
    // v6/v9 form: name@version (the only non-leading `@` separates the version)
    const name = key.slice(0, at);
    const version = key.slice(at + 1);
    return /^\d/.test(version) ? { name, version } : undefined;
  }
  // v5 form: name/version
  const slash = key.lastIndexOf('/');
  if (slash <= 0) return undefined;
  const name = key.slice(0, slash);
  const version = key.slice(slash + 1);
  return /^\d/.test(version) ? { name, version } : undefined;
}

/** Strip pnpm's peer-suffix from a resolved version: `4.17.21(react@18.2.0)` / `4.17.21_react@18` → `4.17.21`. */
function pnpmVersion(v: string): string {
  return v.split('(')[0]!.split('_')[0]!;
}

interface PnpmImporterSection {
  [name: string]: string | { specifier?: string; version?: string };
}

/** Expand a pnpm-lock.yaml (v5/v6/v9 — shapes differ per major, all handled). */
export function enumeratePnpmGraph(lockText: string, declared: Dependency[]): Dependency[] {
  const lock = parse(lockText) as {
    importers?: Record<
      string,
      { dependencies?: PnpmImporterSection; devDependencies?: PnpmImporterSection; optionalDependencies?: PnpmImporterSection }
    >;
    // pre-v6 single-package lockfiles put the root sections at the top level
    dependencies?: PnpmImporterSection;
    devDependencies?: PnpmImporterSection;
    packages?: Record<string, { requiresBuild?: boolean } | null>;
  };

  const all: LockGraph['all'] = [];
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    const parsed = parsePnpmKey(key);
    if (parsed) all.push({ ...parsed, installScript: entry?.requiresBuild === true });
  }

  // Direct-dep pinning from the root importer ('.'), falling back to top-level sections (v5).
  const bySpec = new Map<string, string>();
  const root = lock.importers?.['.'] ?? {
    dependencies: lock.dependencies,
    devDependencies: lock.devDependencies,
  };
  for (const section of [root.dependencies, root.devDependencies, ('optionalDependencies' in root ? root.optionalDependencies : undefined)]) {
    for (const [name, v] of Object.entries(section ?? {})) {
      const spec = typeof v === 'string' ? undefined : v.specifier;
      const version = typeof v === 'string' ? v : v.version;
      if (!version) continue;
      bySpec.set(`${name}@${spec ?? version}`, pnpmVersion(version));
    }
  }
  return assemble({ all, bySpec }, declared);
}

/** Expand a yarn.lock — classic v1 (custom block format) or berry v2+ (YAML). */
export function enumerateYarnGraph(lockText: string, declared: Dependency[]): Dependency[] {
  const graph = lockText.includes('__metadata:') ? parseYarnBerry(lockText) : parseYarnV1(lockText);
  return assemble(graph, declared);
}

/** A yarn spec like `lodash@^4.17.20` or `@babel/core@npm:^7.0.0` → { name, range }. */
function parseYarnSpec(raw: string): { name: string; range: string } | undefined {
  const spec = raw.replace(/^"|"$/g, '');
  const at = spec.indexOf('@', 1); // skip a leading scope `@`
  if (at === -1) return undefined;
  const name = spec.slice(0, at);
  let range = spec.slice(at + 1);
  if (range.startsWith('npm:')) range = range.slice(4); // berry protocol prefix
  return { name, range };
}

/** Classic yarn v1: non-indented `spec, spec:` header lines, indented `version "x"` bodies. */
function parseYarnV1(text: string): LockGraph {
  const all: LockGraph['all'] = [];
  const bySpec = new Map<string, string>();
  const seen = new Set<string>();
  let specs: { name: string; range: string }[] = [];
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    if (!/^\s/.test(line) && line.trimEnd().endsWith(':')) {
      specs = line.trimEnd().slice(0, -1).split(',').map((s) => parseYarnSpec(s.trim()))
        .filter((s): s is { name: string; range: string } => s !== undefined);
      continue;
    }
    const m = line.match(/^\s+version\s+"?([^"\s]+)"?/);
    if (!m || specs.length === 0) continue;
    const version = m[1]!;
    for (const s of specs) {
      bySpec.set(`${s.name}@${s.range}`, version);
      const id = `${s.name}@${version}`;
      if (!seen.has(id)) {
        seen.add(id);
        all.push({ name: s.name, version });
      }
    }
    specs = [];
  }
  return { all, bySpec };
}

/** Yarn berry (v2+): a YAML map of `"spec, spec": { version, resolution }`. */
function parseYarnBerry(text: string): LockGraph {
  const lock = parse(text) as Record<string, { version?: string | number; resolution?: string } | null>;
  const all: LockGraph['all'] = [];
  const bySpec = new Map<string, string>();
  const seen = new Set<string>();
  for (const [key, entry] of Object.entries(lock)) {
    if (key === '__metadata' || !entry?.version) continue;
    if (entry.resolution?.includes('@workspace:')) continue; // the project itself, not a dep
    const version = String(entry.version);
    for (const rawSpec of key.split(',')) {
      const s = parseYarnSpec(rawSpec.trim());
      if (!s) continue;
      bySpec.set(`${s.name}@${s.range}`, version);
      const id = `${s.name}@${version}`;
      if (!seen.has(id)) {
        seen.add(id);
        all.push({ name: s.name, version });
      }
    }
  }
  return { all, bySpec };
}
