import type { Ecosystem } from './types';

// Offline typosquat heuristic: a curated set of high-value package names attackers mimic. A
// dependency whose name is one edit away from one of these (but isn't it) is flagged — the kind of
// malicious lookalike (lodahs→lodash, crossenv→cross-env) that OSV only learns about after the fact.
// Fully local: no network, no key. Conservative (distance 1, len ≥ 4) — surfaced as a soft warning.

const POPULAR: Record<Ecosystem, string[]> = {
  npm: [
    'lodash', 'react', 'react-dom', 'react-native', 'express', 'axios', 'chalk', 'commander',
    'webpack', 'typescript', 'eslint', 'prettier', 'jest', 'mocha', 'vue', 'next', 'nuxt', 'svelte',
    'vite', 'rollup', 'esbuild', 'dotenv', 'cross-env', 'rimraf', 'glob', 'uuid', 'moment', 'dayjs',
    'classnames', 'redux', 'zustand', 'tailwindcss', 'postcss', 'autoprefixer', 'node-fetch',
    'request', 'bluebird', 'underscore', 'ramda', 'socket.io', 'ws', 'mongoose', 'sequelize', 'pg',
    'redis', 'jsonwebtoken', 'bcrypt', 'passport', 'cors', 'helmet', 'morgan', 'nodemon', 'husky',
    'colors', 'color', 'debug', 'semver', 'yargs', 'inquirer', 'ora', 'execa', 'fs-extra',
    'minimist', 'left-pad', 'picocolors', 'commander', 'concurrently',
  ],
  PyPI: [
    'requests', 'urllib3', 'numpy', 'pandas', 'flask', 'django', 'fastapi', 'pytest', 'setuptools',
    'wheel', 'scipy', 'matplotlib', 'pillow', 'boto3', 'click', 'jinja2', 'sqlalchemy', 'pydantic',
    'aiohttp', 'beautifulsoup4', 'scikit-learn', 'tensorflow', 'torch', 'transformers', 'certifi',
    'six', 'pyyaml', 'cryptography', 'python-dateutil', 'virtualenv', 'colorama', 'tqdm', 'rich',
    'httpx', 'typer', 'poetry', 'selenium', 'openai', 'anyio', 'attrs',
  ],
};

/** Strip scope and normalize separators so `cross_env`/`crossenv` compare against `cross-env`. */
function normalize(name: string): string {
  return name.replace(/^@[^/]+\//, '').replace(/[_.]/g, '-').toLowerCase();
}

const NORM: Record<Ecosystem, Set<string>> = {
  npm: new Set(POPULAR.npm.map(normalize)),
  PyPI: new Set(POPULAR.PyPI.map(normalize)),
};

/** True iff the Damerau-Levenshtein distance between a and b is exactly 1 (incl. one transposition). */
function isOneEditApart(a: string, b: string): boolean {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[m][n] === 1;
}

/** The popular package `name` looks like a typosquat of, or undefined if it doesn't. */
export function typosquatOf(name: string, ecosystem: Ecosystem): string | undefined {
  const n = normalize(name);
  if (n.length < 4 || NORM[ecosystem].has(n)) return undefined;
  for (const p of POPULAR[ecosystem]) {
    if (isOneEditApart(n, normalize(p))) return p;
  }
  return undefined;
}
