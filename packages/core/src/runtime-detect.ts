import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { RuntimeName, RuntimeTarget } from './types';

// Auto-detect target runtimes from the version files sitting next to a manifest.
// Detected targets are marked non-explicit: they surface findings but don't fail
// builds on their own (a build that was green yesterday shouldn't turn red because
// a .nvmrc was noticed today) — flags/config make the target explicit.

const FILES: [RuntimeName, string][] = [
  ['node', '.nvmrc'],
  ['node', '.node-version'],
  ['python', '.python-version'],
];

/** Read .nvmrc / .node-version / .python-version from `dir` into runtime targets. */
export function detectRuntimes(dir: string): Partial<Record<RuntimeName, RuntimeTarget>> {
  const out: Partial<Record<RuntimeName, RuntimeTarget>> = {};
  for (const [runtime, file] of FILES) {
    if (out[runtime]) continue; // first hit wins (.nvmrc over .node-version)
    const p = join(dir, file);
    if (!existsSync(p)) continue;
    let raw: string;
    try {
      raw = readFileSync(p, 'utf8');
    } catch {
      continue;
    }
    const version = (raw.split('\n')[0] ?? '').trim().replace(/^v/, '');
    // Only plain numeric versions; aliases ("lts/hydrogen", "system", "pypy3.9") are
    // not comparable targets.
    if (!/^\d+(\.\d+)*$/.test(version)) continue;
    out[runtime] = { runtime, version, source: file, explicit: false };
  }
  return out;
}
