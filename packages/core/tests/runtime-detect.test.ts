import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { detectRuntimes } from '../src/runtime-detect';

const dirs: string[] = [];

function makeDir(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'preflight-detect-'));
  dirs.push(dir);
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
  return dir;
}

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe('detectRuntimes', () => {
  it('reads .nvmrc and .python-version as non-explicit targets', () => {
    const d = makeDir({ '.nvmrc': 'v18.19.0\n', '.python-version': '3.9.6\n' });
    const t = detectRuntimes(d);
    expect(t.node).toMatchObject({ runtime: 'node', version: '18.19.0', source: '.nvmrc', explicit: false });
    expect(t.python).toMatchObject({ runtime: 'python', version: '3.9.6', source: '.python-version' });
  });

  it('prefers .nvmrc over .node-version and skips non-numeric aliases', () => {
    const d = makeDir({ '.nvmrc': '20\n', '.node-version': '18' });
    expect(detectRuntimes(d).node?.source).toBe('.nvmrc');
    const d2 = makeDir({ '.nvmrc': 'lts/hydrogen\n', '.python-version': 'pypy3.9' });
    expect(detectRuntimes(d2)).toEqual({});
  });

  it('returns {} when no version files exist', () => {
    expect(detectRuntimes(makeDir({}))).toEqual({});
  });
});
