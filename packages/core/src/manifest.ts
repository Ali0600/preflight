import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

import type { Dependency, Manifest } from './types';

/** Parse an npm (package.json) or pip (requirements.txt) manifest into a flat dep list. */
export function parseManifest(path: string): Manifest {
  const file = basename(path).toLowerCase();
  if (file === 'package.json') return parseNpm(path);
  if (file.startsWith('requirements') && file.endsWith('.txt')) return parsePip(path);
  throw new Error(`Unsupported manifest: ${file} (expected package.json or requirements*.txt)`);
}

function parseNpm(path: string): Manifest {
  const pkg = JSON.parse(readFileSync(path, 'utf8')) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const deps: Dependency[] = [];
  const add = (obj: Record<string, string> | undefined, dev: boolean) => {
    for (const [name, range] of Object.entries(obj ?? {})) deps.push({ name, range, dev });
  };
  add(pkg.dependencies, false);
  add(pkg.devDependencies, true);

  // Resolve installed versions from the lockfile when present (npm lockfileVersion 2/3).
  const lock = join(dirname(path), 'package-lock.json');
  if (existsSync(lock)) {
    const lj = JSON.parse(readFileSync(lock, 'utf8')) as {
      packages?: Record<string, { version?: string }>;
    };
    const packages = lj.packages ?? {};
    for (const d of deps) {
      const entry = packages[`node_modules/${d.name}`];
      if (entry?.version) d.version = entry.version;
    }
  }
  return { ecosystem: 'npm', path, dependencies: deps };
}

function parsePip(path: string): Manifest {
  const deps: Dependency[] = [];
  for (const raw of readFileSync(path, 'utf8').split('\n')) {
    const line = raw.split('#')[0]?.trim() ?? '';
    if (!line || line.startsWith('-')) continue; // skip blanks, comments, -r/-e flags
    const m = line.match(/^([A-Za-z0-9._-]+)\s*(.*)$/);
    if (!m) continue;
    const name = m[1] ?? '';
    const range = (m[2] ?? '').trim();
    const pinned = range.match(/==\s*([0-9][^,\s]*)/);
    deps.push({ name, range, dev: false, version: pinned?.[1] });
  }
  return { ecosystem: 'PyPI', path, dependencies: deps };
}
