import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { parseManifest } from '../src/manifest';

const fixture = (p: string) => fileURLToPath(new URL(`./fixtures/${p}`, import.meta.url));

describe('parseManifest — npm', () => {
  const m = parseManifest(fixture('npm/package.json'));

  it('flags ecosystem and splits deps vs devDeps', () => {
    expect(m.ecosystem).toBe('npm');
    expect(m.dependencies.find((d) => d.name === 'left-pad')).toMatchObject({
      range: '^1.3.0',
      dev: false,
    });
    expect(m.dependencies.find((d) => d.name === 'vitest')?.dev).toBe(true);
  });

  it('resolves installed versions from package-lock.json', () => {
    expect(m.dependencies.find((d) => d.name === 'left-pad')?.version).toBe('1.3.0');
    expect(m.dependencies.find((d) => d.name === 'vitest')?.version).toBe('2.1.8');
  });
});

describe('parseManifest — pip', () => {
  const m = parseManifest(fixture('requirements.txt'));

  it('pins == versions and leaves ranges unpinned', () => {
    expect(m.ecosystem).toBe('PyPI');
    expect(m.dependencies.find((d) => d.name === 'requests')?.version).toBe('2.31.0');
    expect(m.dependencies.find((d) => d.name === 'django')?.version).toBe('4.2.1'); // tolerates spaces
    expect(m.dependencies.find((d) => d.name === 'flask')?.version).toBeUndefined();
  });

  it('skips comments and -r include lines', () => {
    const names = m.dependencies.map((d) => d.name);
    expect(names).toEqual(['requests', 'flask', 'django']);
  });
});

describe('parseManifest — unsupported', () => {
  it('throws on an unknown manifest', () => {
    expect(() => parseManifest('/tmp/Gemfile')).toThrow(/Unsupported manifest/);
  });
});
