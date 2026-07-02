import { describe, expect, it } from 'vitest';

import { computeRuntimeCompat } from '../src/runtime-compat';
import type { RuntimeMeta } from '../src/runtimes';
import type { RuntimeTarget } from '../src/types';

const PY39: RuntimeTarget = {
  runtime: 'python',
  version: '3.9',
  source: '--python flag',
  explicit: true,
};

// uvicorn-shaped history: 0.40.0 dropped Python 3.9 (the real 2026-07-02 incident).
const UVICORN: RuntimeMeta = {
  latest: '0.49.0',
  constraints: {
    '0.30.0': '>=3.8',
    '0.39.0': '>=3.9',
    '0.40.0': '>=3.10',
    '0.49.0': '>=3.10',
    '0.49.0b1': '>=3.10', // prerelease — must never become a floor/boundary
  },
};

describe('computeRuntimeCompat (the uvicorn incident, PyPI)', () => {
  it('flags a floor that no compatible version satisfies (uvicorn>=0.49 on 3.9)', () => {
    const c = computeRuntimeCompat({ range: '>=0.49' }, UVICORN, PY39, 'PyPI');
    expect(c).toBeDefined();
    expect(c!.rangeUnsatisfiable).toBe(true);
    expect(c!.maxCompatible).toBe('0.39.0');
    expect(c!.firstIncompatible).toBe('0.40.0'); // the Dependabot ignore boundary
    expect(c!.constraint).toBe('>=3.10');
    expect(c!.latestIncompatible).toBe(true);
  });

  it('flags a locked version that cannot install on the target', () => {
    const c = computeRuntimeCompat({ range: '>=0.30', version: '0.49.0' }, UVICORN, PY39, 'PyPI');
    expect(c!.resolvedIncompatible).toBe(true);
    expect(c!.rangeUnsatisfiable).toBe(false); // 0.30.0/0.39.0 still satisfy the range
  });

  it('a healthy floor still warns that the latest release dropped the target', () => {
    const c = computeRuntimeCompat({ range: '>=0.30,<0.40' }, UVICORN, PY39, 'PyPI');
    expect(c!.rangeUnsatisfiable).toBe(false);
    expect(c!.resolvedIncompatible).toBe(false);
    expect(c!.latestIncompatible).toBe(true); // the next major bump will break
  });

  it('returns undefined when the target is fully compatible', () => {
    const py311: RuntimeTarget = { ...PY39, version: '3.11' };
    expect(computeRuntimeCompat({ range: '>=0.49' }, UVICORN, py311, 'PyPI')).toBeUndefined();
  });

  it('reports the oldest constraint when nothing installs on the target at all', () => {
    const py27: RuntimeTarget = { ...PY39, version: '2.7' };
    const c = computeRuntimeCompat({ range: '>=0.30' }, UVICORN, py27, 'PyPI');
    expect(c!.maxCompatible).toBeUndefined();
    expect(c!.firstIncompatible).toBe('0.30.0');
  });
});

describe('computeRuntimeCompat (npm engines)', () => {
  const NODE18: RuntimeTarget = { runtime: 'node', version: '18', source: '.nvmrc', explicit: false };
  const PKG: RuntimeMeta = {
    latest: '3.0.0',
    constraints: {
      '1.0.0': null, // no engines declared = compatible
      '2.0.0': '>=18',
      '3.0.0': '>=20',
    },
  };

  it('treats undeclared engines as compatible and finds the boundary', () => {
    const c = computeRuntimeCompat({ range: '^3.0.0' }, PKG, NODE18, 'npm');
    expect(c!.rangeUnsatisfiable).toBe(true);
    expect(c!.maxCompatible).toBe('2.0.0');
    expect(c!.firstIncompatible).toBe('3.0.0');
    expect(c!.constraint).toBe('>=20');
  });

  it('caret ranges that still have a compatible version pass', () => {
    const c = computeRuntimeCompat({ range: '^2.0.0' }, PKG, NODE18, 'npm');
    expect(c?.rangeUnsatisfiable ?? false).toBe(false);
  });

  it('returns undefined when there is no usable metadata', () => {
    expect(
      computeRuntimeCompat({ range: '^1.0.0' }, { constraints: {} }, NODE18, 'npm'),
    ).toBeUndefined();
  });
});
