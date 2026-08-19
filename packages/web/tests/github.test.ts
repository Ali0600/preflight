import { describe, expect, it } from 'vitest';

import { buildFetchPlan, displayPath, parseGitHubUrl } from '../app/api/repo/github';

const ok = (input: string) => {
  const r = parseGitHubUrl(input);
  if (!r.ok) throw new Error(`expected ${input} to parse, got: ${r.error}`);
  return r.target;
};
const bad = (input: string) => {
  const r = parseGitHubUrl(input);
  expect(r.ok, `expected ${input} to be REJECTED`).toBe(false);
  return r;
};

describe('parseGitHubUrl — accepted forms', () => {
  it('bare owner/repo defaults to the HEAD ref and the repo root', () => {
    // HEAD resolves the default branch on raw.githubusercontent.com (probed live), so we never
    // need an API call just to learn what the default branch is called.
    expect(ok('Ali0600/preflight')).toEqual({ owner: 'Ali0600', repo: 'preflight', ref: 'HEAD', dir: '' });
  });

  it('tolerates the shapes people actually copy out of a browser', () => {
    const target = { owner: 'Ali0600', repo: 'preflight', ref: 'HEAD', dir: '' };
    expect(ok('https://github.com/Ali0600/preflight')).toEqual(target);
    expect(ok('http://github.com/Ali0600/preflight')).toEqual(target);
    expect(ok('https://www.github.com/Ali0600/preflight')).toEqual(target);
    expect(ok('github.com/Ali0600/preflight')).toEqual(target);
    expect(ok('https://github.com/Ali0600/preflight/')).toEqual(target);
    expect(ok('https://github.com/Ali0600/preflight.git')).toEqual(target);
    expect(ok('  https://github.com/Ali0600/preflight  ')).toEqual(target);
    expect(ok('https://github.com/Ali0600/preflight?tab=readme-ov-file#install')).toEqual(target);
  });

  it('reads a /tree/ ref, including a tag, and an optional subdirectory', () => {
    expect(ok('https://github.com/o/r/tree/main')).toMatchObject({ ref: 'main', dir: '' });
    expect(ok('https://github.com/o/r/tree/v1.2.3')).toMatchObject({ ref: 'v1.2.3', dir: '' });
    expect(ok('https://github.com/o/r/tree/main/packages/web')).toMatchObject({
      ref: 'main',
      dir: 'packages/web',
    });
  });

  it('reads a /blob/ URL pointed straight at a manifest', () => {
    expect(ok('https://github.com/o/r/blob/main/backend/requirements-dev.txt')).toMatchObject({
      ref: 'main',
      dir: 'backend',
      manifest: 'requirements-dev.txt',
    });
    expect(ok('https://github.com/o/r/blob/main/Cargo.lock')).toMatchObject({
      dir: '',
      manifest: 'Cargo.lock',
    });
  });

  it('pins the v1 behaviour for a branch name containing a slash', () => {
    // GitHub URLs are ambiguous here — `feat/br` could be a branch or a branch + directory, and
    // nothing in the URL distinguishes them without an API call. v1 takes the first segment as
    // the ref; the fetch then 404s and the route's message says slash-branches aren't supported.
    expect(ok('https://github.com/o/r/tree/feat/br/dir')).toMatchObject({ ref: 'feat', dir: 'br/dir' });
  });
});

describe('parseGitHubUrl — rejected inputs (every one of these could otherwise reach fetch)', () => {
  it('rejects empty and oversized input', () => {
    bad('');
    bad('   ');
    bad('o/' + 'r'.repeat(600));
  });

  it('rejects path traversal in every position', () => {
    bad('../etc/passwd');
    bad('o/..');
    bad('../r');
    bad('o/r/tree/..');
    bad('o/r/tree/main/../../etc');
    bad('o/r/blob/main/../../../etc/passwd');
  });

  it('rejects percent-encoding outright (no smuggled separators)', () => {
    bad('o/r/tree/main/%2e%2e/x');
    bad('%2e%2e/r');
    bad('o/r/tree/ma%2fin');
  });

  it('rejects other hosts, schemes and userinfo tricks', () => {
    bad('https://evil.com/o/r');
    bad('https://github.com@evil.com/o/r');
    bad('//evil.com/o/r');
    bad('git@github.com:o/r.git');
    bad('ftp://github.com/o/r');
    bad('https://raw.githubusercontent.com/o/r');
    bad('file:///etc/passwd');
    bad('http://169.254.169.254/latest/meta-data');
  });

  it('rejects names outside GitHub charset rules', () => {
    bad('ownér/repo');
    bad('-owner/repo');
    bad('o\\r');
    bad('own er/repo');
    bad('owner/.');
    bad('owner/..');
    bad('owner');
  });

  it('rejects GitHub URLs that are not a tree/blob location', () => {
    bad('https://github.com/o/r/pull/1');
    bad('https://github.com/o/r/releases');
    bad('https://github.com/o/r/issues/42');
    bad('https://github.com/o/r/blob/main'); // blob with no file path
  });

  it('rejects a /blob/ URL that does not point at a manifest', () => {
    // Otherwise we would fetch (and try to parse) an arbitrary repo file.
    bad('https://github.com/o/r/blob/main/README.md');
    bad('https://github.com/o/r/blob/main/src/index.ts');
    bad('https://github.com/o/r/blob/main/Cargo.toml'); // requirements, not resolved versions
  });
});

describe('buildFetchPlan', () => {
  const urls = (input: string) => buildFetchPlan(ok(input)).map((e) => e.url);

  it('probes a fixed candidate list at the repo root — never a directory listing', () => {
    // A fixed list keeps this API-less: the GitHub API's 60/hr per-IP budget would be shared by
    // every visitor to the deployed dashboard.
    const plan = buildFetchPlan(ok('o/r'));
    expect(plan.filter((e) => e.kind === 'manifest').map((e) => e.name)).toEqual([
      'package.json',
      'requirements.txt',
      'Gemfile.lock',
      'go.mod',
      'Cargo.lock',
    ]);
    expect(plan.filter((e) => e.kind === 'lockfile').map((e) => e.name)).toEqual([
      'package-lock.json',
      'pnpm-lock.yaml',
      'yarn.lock',
    ]);
    expect(plan).toHaveLength(8);
    expect(plan[0]!.url).toBe('https://raw.githubusercontent.com/o/r/HEAD/package.json');
  });

  it('prefixes the subdirectory in both the key and the URL', () => {
    const plan = buildFetchPlan(ok('https://github.com/o/r/tree/main/packages/web'));
    expect(plan[0]!.name).toBe('packages/web/package.json');
    expect(plan[0]!.url).toBe('https://raw.githubusercontent.com/o/r/main/packages/web/package.json');
  });

  it('a blob URL fetches just that manifest — plus lockfiles only for package.json', () => {
    expect(urls('https://github.com/o/r/blob/main/go.mod')).toEqual([
      'https://raw.githubusercontent.com/o/r/main/go.mod',
    ]);
    const pkg = buildFetchPlan(ok('https://github.com/o/r/blob/main/app/package.json'));
    expect(pkg.map((e) => e.name)).toEqual([
      'app/package.json',
      'app/package-lock.json',
      'app/pnpm-lock.yaml',
      'app/yarn.lock',
    ]);
  });

  it('every generated URL is anchored to raw.githubusercontent.com and traversal-free', () => {
    const inputs = [
      'o/r',
      'https://github.com/o/r/tree/v1.2.3/a/b/c',
      'https://github.com/o/r/blob/main/deep/nested/dir/Gemfile.lock',
    ];
    for (const input of inputs) {
      for (const url of urls(input)) {
        expect(url.startsWith('https://raw.githubusercontent.com/')).toBe(true);
        expect(url).not.toContain('..');
        expect(url.slice('https://'.length)).not.toContain('//');
      }
    }
  });
});

describe('displayPath', () => {
  it('renders a logical repo path instead of the temp-dir path the engine returns', () => {
    expect(displayPath(ok('https://github.com/o/r/tree/main/packages/web'), 'packages/web/package.json')).toBe(
      'o/r/packages/web/package.json@main',
    );
    expect(displayPath(ok('rails/rails'), 'Gemfile.lock')).toBe('rails/rails/Gemfile.lock@HEAD');
  });
});
