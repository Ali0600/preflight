import { describe, expect, it } from 'vitest';

import { typosquatOf } from '../src/typosquat';

describe('typosquatOf', () => {
  it('flags single-edit lookalikes of popular packages', () => {
    expect(typosquatOf('lodahs', 'npm')).toBe('lodash'); // transposition
    expect(typosquatOf('expres', 'npm')).toBe('express'); // deletion
    expect(typosquatOf('crossenv', 'npm')).toBe('cross-env'); // missing separator
    expect(typosquatOf('reqeusts', 'PyPI')).toBe('requests'); // transposition
  });

  it('does not flag the real package or clearly different names', () => {
    expect(typosquatOf('lodash', 'npm')).toBeUndefined();
    expect(typosquatOf('cross-env', 'npm')).toBeUndefined();
    expect(typosquatOf('react', 'npm')).toBeUndefined();
    expect(typosquatOf('my-internal-utils', 'npm')).toBeUndefined();
    expect(typosquatOf('numpy', 'PyPI')).toBeUndefined();
  });

  it('ignores very short names (too noisy)', () => {
    expect(typosquatOf('ws', 'npm')).toBeUndefined();
    expect(typosquatOf('pg', 'npm')).toBeUndefined();
  });

  it('normalizes scope and separators before comparing', () => {
    expect(typosquatOf('cross_env', 'npm')).toBeUndefined(); // == cross-env, not a squat
  });
});
