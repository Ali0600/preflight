import { describe, expect, it } from 'vitest';

import {
  compareSemver,
  parseSemver,
  rangeAdmitsSeries,
  satisfies,
} from '../src/semver';

describe('parseSemver / compareSemver', () => {
  it('parses full versions incl. prerelease and build metadata', () => {
    expect(parseSemver('1.2.3')).toEqual({ major: 1, minor: 2, patch: 3 });
    expect(parseSemver('v18.19.0')).toEqual({ major: 18, minor: 19, patch: 0 });
    expect(parseSemver('1.0.0-beta.2+build.5')?.prerelease).toEqual(['beta', '2']);
    expect(parseSemver('1.2')).toBeUndefined(); // partials are range syntax, not versions
    expect(parseSemver('not-a-version')).toBeUndefined();
  });

  it('orders prereleases below their release, numerics before alphanumerics', () => {
    const cmp = (a: string, b: string) => compareSemver(parseSemver(a)!, parseSemver(b)!);
    expect(cmp('1.0.0-alpha', '1.0.0')).toBeLessThan(0);
    expect(cmp('1.0.0-alpha.1', '1.0.0-alpha.beta')).toBeLessThan(0); // 1 < beta
    expect(cmp('1.0.0-alpha', '1.0.0-alpha.1')).toBeLessThan(0); // shorter first
    expect(cmp('2.0.0', '10.0.0')).toBeLessThan(0); // numeric, not lexicographic
  });
});

describe('satisfies', () => {
  const table: [string, string, boolean][] = [
    ['1.7.2', '^1.2.0', true],
    ['2.0.0', '^1.2.0', false],
    ['0.2.5', '^0.2.3', true],
    ['0.3.0', '^0.2.3', false], // caret on 0.x pins the minor
    ['1.2.9', '~1.2.3', true],
    ['1.3.0', '~1.2.3', false],
    ['1.5.0', '1.x', true],
    ['2.0.0', '1.x', false],
    ['1.2.7', '1.2.*', true],
    ['2.3.0', '1.2 - 2.3', true], // hyphen upper partial fills to <2.4.0
    ['2.4.0', '1.2 - 2.3', false],
    ['15.0.0', '>=14 <16', true],
    ['16.0.0', '>=14 <16', false],
    ['13.0.0', '^12 || >=14', false],
    ['14.2.0', '^12 || >=14', true],
    ['5.0.0', '*', true],
  ];
  it.each(table)('%s vs "%s" -> %s', (version, range, expected) => {
    expect(satisfies(version, range)).toBe(expected);
  });

  it('returns undefined for unparseable input instead of guessing', () => {
    expect(satisfies('garbage', '^1.0.0')).toBeUndefined();
    expect(satisfies('1.0.0', 'workspace:*')).toBeUndefined();
    // one bad || branch cannot prove "false"
    expect(satisfies('9.0.0', '^1.0.0 || workspace:*')).toBeUndefined();
    // ...but a good branch can still prove "true"
    expect(satisfies('1.5.0', '^1.0.0 || workspace:*')).toBe(true);
  });
});

describe('rangeAdmitsSeries (engines vs target runtime)', () => {
  const table: [string, string, boolean][] = [
    ['>=18', '18', true],
    ['>=18.17', '18', true], // some 18.x satisfies >=18.17
    ['>=18.17', '18.2.0', false], // a full target is a point, not a series
    ['>=20', '18', false],
    ['<18.5', '18', true], // 18.0.0..18.4.x intersects
    ['^12 || >=14', '13', false],
    ['^12 || >=14', '14', true],
    ['>=0.10.3 <15', '14', true],
    ['16 || 18 || 20', '18', true],
    ['16 || 18 || 20', '19', false],
  ];
  it.each(table)('engines "%s" vs target %s -> %s', (range, target, expected) => {
    expect(rangeAdmitsSeries(range, target)).toBe(expected);
  });

  it('returns undefined (treat-as-compatible) when it cannot tell', () => {
    expect(rangeAdmitsSeries('what-even-is-this', '18')).toBeUndefined();
    expect(rangeAdmitsSeries('>=18', 'not-a-version')).toBeUndefined();
  });
});
