import { describe, expect, it } from 'vitest';

import {
  comparePep440,
  parsePep440,
  specifierAdmits,
  specifierAdmitsSeries,
} from '../src/pep440';

describe('parsePep440 / comparePep440', () => {
  it('parses releases, prereleases, post and dev segments', () => {
    expect(parsePep440('3.9')).toEqual({ epoch: 0, release: [3, 9] });
    expect(parsePep440('0.49.0b1')?.pre).toEqual(['b', 1]);
    expect(parsePep440('1.0.post2')?.post).toBe(2);
    expect(parsePep440('1.0.dev3')?.dev).toBe(3);
    expect(parsePep440('2!1.0')?.epoch).toBe(2);
    expect(parsePep440('not a version')).toBeUndefined();
  });

  it('orders per PEP 440: dev < a < b < rc < final < post', () => {
    const cmp = (a: string, b: string) => comparePep440(parsePep440(a)!, parsePep440(b)!);
    expect(cmp('0.49.0b1', '0.49.0')).toBeLessThan(0); // the uvicorn prerelease trap
    expect(cmp('1.0.dev1', '1.0a1')).toBeLessThan(0);
    expect(cmp('1.0a1', '1.0b1')).toBeLessThan(0);
    expect(cmp('1.0rc1', '1.0')).toBeLessThan(0);
    expect(cmp('1.0', '1.0.post1')).toBeLessThan(0);
    expect(cmp('3.9', '3.10')).toBeLessThan(0); // numeric segments, not lexicographic
    expect(cmp('3.9', '3.9.0')).toBe(0); // trailing zeros equal
    expect(cmp('1!0.5', '2.0')).toBeGreaterThan(0); // epoch dominates
  });
});

describe('specifierAdmits (a concrete version vs a specifier set)', () => {
  const table: [string, string, boolean][] = [
    ['>=0.49', '0.49.0', true],
    ['>=0.49', '0.39.0', false],
    ['>=0.30,<0.40', '0.39.0', true],
    ['>=0.30,<0.40', '0.40.0', false],
    ['==3.9.*', '3.9.7', true],
    ['==3.9.*', '3.10.0', false],
    ['!=3.9.*', '3.9.7', false],
    ['~=1.4', '1.9.0', true], // ~=1.4 -> >=1.4, ==1.*
    ['~=1.4', '2.0.0', false],
    ['~=1.4.2', '1.4.9', true],
    ['~=1.4.2', '1.5.0', false],
  ];
  it.each(table)('"%s" admits %s -> %s', (spec, version, expected) => {
    expect(specifierAdmits(spec, version)).toBe(expected);
  });

  it('degrades to undefined only when nothing was evaluable', () => {
    expect(specifierAdmits('===1.0.0', '1.0.0')).toBeUndefined();
    // a parseable atom that says no is trusted even next to an unparseable one
    expect(specifierAdmits('===1.0.0,>=2.0', '1.0.0')).toBe(false);
  });
});

describe('specifierAdmitsSeries (Requires-Python vs target runtime series)', () => {
  const table: [string, string, boolean][] = [
    ['>=3.10', '3.9', false], // the uvicorn 0.49 incident
    ['>=3.9', '3.9', true],
    ['>=3.8', '3.9', true],
    ['>=3.9.2', '3.9', true], // some 3.9.x satisfies it
    ['<3.9', '3.9', false],
    ['<=3.9', '3.9', true],
    ['>=2.7,!=3.0.*,!=3.1.*', '3.9', true],
    ['!=3.9.*', '3.9', false], // the hole covers the whole series
    ['!=3.9.7', '3.9', true], // a point hole leaves the rest of the series
    ['==3.9.*', '3.9', true],
    ['==3.10.*', '3.9', false],
    ['~=3.8', '3.9', true],
    ['~=3.8', '4.0', false],
    ['>=3.6,<4', '3.9', true],
  ];
  it.each(table)('"%s" vs Python %s -> %s', (spec, target, expected) => {
    expect(specifierAdmitsSeries(spec, target)).toBe(expected);
  });

  it('returns undefined (treat-as-compatible) when nothing was evaluable', () => {
    expect(specifierAdmitsSeries('===3.9', '3.9')).toBeUndefined();
    expect(specifierAdmitsSeries('>=3.10', 'not-a-version')).toBeUndefined();
  });
});
