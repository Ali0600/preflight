import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { parseManifest, parseManifestContent } from '../src/manifest';

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
    expect(m.dependencies.find((d) => d.name === 'left-pad')?.direct).toBe(true);
  });

  it('flags packages that run install scripts (lockfile hasInstallScript)', () => {
    expect(m.dependencies.find((d) => d.name === 'left-pad')?.installScript).toBe(true);
    expect(m.dependencies.find((d) => d.name === 'vitest')?.installScript).toBeUndefined();
  });

  it('enumerates the full transitive graph from the lockfile', () => {
    // hoisted transitive (top-level node_modules) + nested transitive
    expect(m.dependencies.find((d) => d.name === 'tinypool')).toMatchObject({
      version: '1.0.0',
      direct: false,
    });
    expect(m.dependencies.find((d) => d.name === 'tinyspy')).toMatchObject({
      version: '3.0.2',
      direct: false,
    });
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

describe('parseManifestContent — npm exact-pin inference (no lockfile)', () => {
  // The dashboard pastes a manifest with no lockfile, so an exact pin is the resolved version;
  // a range stays unresolved (won't be CVE-queried).
  const m = parseManifestContent(
    'package.json',
    JSON.stringify({
      dependencies: { 'react-native': '0.85.3', expo: '~56.0.12', lodash: '^4.17.0' },
    }),
  );
  const ver = (name: string) => m.dependencies.find((d) => d.name === name)?.version;

  it('treats an exact semver as the version', () => {
    expect(ver('react-native')).toBe('0.85.3');
  });

  it('leaves ranged specs (^ / ~) unresolved', () => {
    expect(ver('expo')).toBeUndefined();
    expect(ver('lodash')).toBeUndefined();
  });
});
