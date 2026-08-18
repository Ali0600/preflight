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

  it('propagates the lockfile dev flag to transitives — prod-reachable stays dev: false (#33)', () => {
    // tinypool/tinyspy are only reachable via vitest (a devDependency): lockfile "dev": true.
    expect(m.dependencies.find((d) => d.name === 'tinypool')?.dev).toBe(true);
    expect(m.dependencies.find((d) => d.name === 'tinyspy')?.dev).toBe(true);
    // left-pad is a real dependency — no dev flag in the lockfile → prod scope.
    expect(m.dependencies.find((d) => d.name === 'left-pad')?.dev).toBe(false);
  });

  it('records that a lockfile expanded the graph', () => {
    expect(m.lockfile).toBe(true);
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

  it('has no lockfile concept (flag stays unset)', () => {
    expect(m.lockfile).toBeUndefined();
  });
});

describe('parseManifest — RubyGems (Gemfile.lock)', () => {
  const m = parseManifest(fixture('ruby/Gemfile.lock'));
  const dep = (name: string) => m.dependencies.find((d) => d.name === name);

  it('is a self-locked manifest: resolved versions straight from the text', () => {
    expect(m.ecosystem).toBe('RubyGems');
    expect(m.lockfile).toBe(true); // no sibling lockfile to find — this file IS the graph
    expect(dep('rails')?.version).toBe('7.0.0');
    expect(dep('concurrent-ruby')?.version).toBe('1.2.2');
  });

  it('tags DEPENDENCIES entries direct (with their requirement) and the rest transitive', () => {
    expect(dep('rails')).toMatchObject({ direct: true, range: '~> 7.0.0' });
    expect(dep('puma')).toMatchObject({ direct: true, range: '~> 6.4' });
    expect(dep('nokogiri')).toMatchObject({ direct: true, range: '' }); // declared without a requirement
    expect(dep('nio4r')).toMatchObject({ direct: false, range: '' });
    expect(dep('racc')?.direct).toBe(false);
  });

  it('strips the platform suffix from a version', () => {
    // `nokogiri (1.13.0-x86_64-linux)` — the platform must not reach OSV as part of the version.
    expect(dep('nokogiri')?.version).toBe('1.13.0');
  });

  it('skips PATH (local) gems but keeps GIT-sourced ones', () => {
    // `billing` is an in-repo engine: its name is arbitrary and must never inherit a
    // rubygems.org gem's advisories. A git dep is a fork of a real gem, so it stays.
    expect(dep('billing')).toBeUndefined();
    expect(dep('forked-gem')).toMatchObject({ version: '2.1.0', direct: true });
  });

  it('ignores dependency edges, PLATFORMS, RUBY VERSION and BUNDLED WITH', () => {
    const names = m.dependencies.map((d) => d.name);
    expect(names).not.toContain('ruby'); // "RUBY VERSION\n   ruby 3.2.2p53"
    expect(names).not.toContain('2.4.10'); // "BUNDLED WITH"
    expect(names).not.toContain('x86_64-linux'); // PLATFORMS
    // Every gem appears exactly once even though most are also listed as edges under others.
    expect(new Set(names).size).toBe(names.length);
  });

  it('treats every gem as prod scope (Bundler groups live in the Gemfile, not the lock)', () => {
    expect(m.dependencies.every((d) => d.dev === false)).toBe(true);
  });
});

describe('parseManifest — Go (go.mod)', () => {
  const m = parseManifest(fixture('go/go.mod'));
  const dep = (name: string) => m.dependencies.find((d) => d.name === name);

  it('reads the pruned module graph, single-line and block requires alike', () => {
    expect(m.ecosystem).toBe('Go');
    expect(m.lockfile).toBe(true); // since Go 1.17 go.mod IS the full graph
    expect(dep('github.com/gin-gonic/gin')?.version).toBe('v1.9.0'); // single-line require
    expect(dep('golang.org/x/net')?.version).toBe('v0.7.0'); // block require
  });

  it('passes versions through verbatim (v prefix, +incompatible)', () => {
    // Verified live that OSV accepts every form — normalising would risk breaking a match.
    expect(dep('github.com/dgrijalva/jwt-go')?.version).toBe('v3.2.0+incompatible');
  });

  it('tags // indirect modules transitive', () => {
    expect(dep('github.com/gin-gonic/gin')?.direct).toBe(true);
    expect(dep('golang.org/x/net')?.direct).toBe(false);
    expect(dep('golang.org/x/text')?.direct).toBe(false);
  });

  it('scans the replacement module, not the replaced one', () => {
    // `replace upstream/lib => example/lib-fork v1.4.2` — the fork is the code that gets built.
    expect(dep('github.com/upstream/lib')).toBeUndefined();
    expect(dep('github.com/example/lib-fork')).toMatchObject({ version: 'v1.4.2', direct: true });
  });

  it('drops a module replaced by a local path', () => {
    // Local code in this repo: its import path must not inherit a real module's advisories.
    expect(dep('github.com/example/internal')).toBeUndefined();
  });

  it('ignores a replace whose left side is not required, plus exclude/retract', () => {
    // "A replace directive has no effect if the module version on the left side is not required."
    expect(dep('github.com/some/other')).toBeUndefined();
    expect(dep('github.com/never/required')).toBeUndefined();
    // Excluded modules are ones the build deliberately avoids — in BOTH the single-line and the
    // block form (only the block form can be mistaken for a require list).
    expect(dep('github.com/bad/pkg')).toBeUndefined();
    expect(dep('github.com/worse/pkg')).toBeUndefined();
    expect(dep('github.com/awful/pkg')).toBeUndefined();
    // retract entries are about THIS module's own releases, not dependencies.
    expect(m.dependencies.some((d) => d.name.startsWith('v0.'))).toBe(false);
  });

  it('reports the stdlib from a toolchain directive', () => {
    expect(dep('stdlib')).toMatchObject({ version: '1.21.0', direct: true });
  });

  it('does NOT infer stdlib from a bare go directive', () => {
    // The `go` line is a MINIMUM — libraries hold it low on purpose for compatibility, so
    // treating it as the build version would invent the whole stdlib CVE backlog for them.
    const bare = parseManifestContent('go.mod', 'module x\n\ngo 1.21.0\n\nrequire a/b v1.0.0\n');
    expect(bare.dependencies.find((d) => d.name === 'stdlib')).toBeUndefined();
    expect(bare.dependencies).toHaveLength(1);
  });
});

describe('parseManifest — unsupported', () => {
  it('throws on an unknown manifest', () => {
    // A bare Gemfile carries requirements but no resolved versions — only the lock is scannable.
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

  it('marks the scan as lockfile-less (drives the "direct deps only" hint)', () => {
    expect(m.lockfile).toBe(false);
  });
});
