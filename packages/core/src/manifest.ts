import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

import type { Dependency, Ecosystem, Manifest } from './types';

/** Pick the parser for a manifest filename, or throw if it isn't one we support. */
function ecosystemFor(file: string): Ecosystem {
  const f = file.toLowerCase();
  if (f === 'package.json') return 'npm';
  if (f.startsWith('requirements') && f.endsWith('.txt')) return 'PyPI';
  throw new Error(`Unsupported manifest: ${file} (expected package.json or requirements*.txt)`);
}

/**
 * Parse manifest *text* (no filesystem access) into a flat dep list — used to read a base-ref
 * manifest fetched over the API (the Action) or pasted into a textarea (the dashboard). npm
 * versions stay unresolved here because the lockfile isn't available; `parseManifest` fills
 * them in from the sibling lockfile when reading off disk.
 */
export function parseManifestContent(filename: string, content: string): Manifest {
  const ecosystem = ecosystemFor(basename(filename));
  const dependencies = ecosystem === 'npm' ? parseNpm(content) : parsePip(content);
  return { ecosystem, path: filename, dependencies };
}

/** Parse an npm (package.json) or pip (requirements.txt) manifest file into a flat dep list. */
export function parseManifest(path: string): Manifest {
  ecosystemFor(basename(path)); // reject unsupported types before touching the filesystem
  const manifest = parseManifestContent(path, readFileSync(path, 'utf8'));
  if (manifest.ecosystem === 'npm') resolveNpmLockVersions(path, manifest.dependencies);
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
      deps.push({ name, range, dev, version: exactPin(range) });
  };
  add(pkg.dependencies, false);
  add(pkg.devDependencies, true);
  return deps;
}

/** Resolve installed versions from the sibling lockfile when present (npm lockfileVersion 2/3). */
function resolveNpmLockVersions(path: string, deps: Dependency[]): void {
  const lock = join(dirname(path), 'package-lock.json');
  if (!existsSync(lock)) return;
  const lj = JSON.parse(readFileSync(lock, 'utf8')) as {
    packages?: Record<string, { version?: string }>;
  };
  const packages = lj.packages ?? {};
  for (const d of deps) {
    const entry = packages[`node_modules/${d.name}`];
    if (entry?.version) d.version = entry.version;
  }
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
