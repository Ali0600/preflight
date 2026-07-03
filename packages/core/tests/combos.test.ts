import { describe, expect, it } from 'vitest';

import { findComboHolds } from '../src/combos';
import type { RuntimeMeta } from '../src/runtimes';
import type { RuntimeTarget } from '../src/types';

const NODE22: RuntimeTarget = { runtime: 'node', version: '22', source: '--node flag', explicit: true };

// The T5 shape: eslint 9.x and 10.x both exist; 10.x breaks beside eslint-config-next ≤16.
const ESLINT_META: RuntimeMeta = {
  latest: '10.6.0',
  constraints: {
    '9.38.0': '>=18',
    '9.39.4': '>=18',
    '10.0.0': '>=20',
    '10.6.0': '>=20',
    '11.0.0-beta.1': '>=20', // prerelease — never a fallback candidate
  },
};

const rec = (entries: [string, string | undefined][]) => new Map(entries);
const metaFor = (m: Record<string, RuntimeMeta>) => (n: string) => m[n];

describe('findComboHolds (issue #31)', () => {
  it('holds eslint back when planned beside a broken eslint-config-next', () => {
    const holds = findComboHolds(
      rec([
        ['eslint', '10.6.0'],
        ['eslint-config-next', '16.2.10'],
      ]),
      metaFor({ eslint: ESLINT_META }),
      NODE22,
      'npm',
    );
    expect(holds.get('eslint')).toMatchObject({
      fallback: '9.39.4', // newest known-good release (prerelease 11.x ignored)
      firstBad: '10.0.0', // the dependabot ignore boundary
      withVersion: '16.2.10',
    });
  });

  it('does not fire when the pair is absent or already compatible', () => {
    const meta = metaFor({ eslint: ESLINT_META });
    // subject alone
    expect(findComboHolds(rec([['eslint', '10.6.0']]), meta, NODE22, 'npm').size).toBe(0);
    // subject already on a known-good version
    expect(
      findComboHolds(rec([['eslint', '9.39.4'], ['eslint-config-next', '16.2.10']]), meta, NODE22, 'npm').size,
    ).toBe(0);
    // the pair member has moved past the broken range
    expect(
      findComboHolds(rec([['eslint', '10.6.0'], ['eslint-config-next', '17.0.0']]), meta, NODE22, 'npm').size,
    ).toBe(0);
  });

  it("an unparseable version never triggers a hold (satisfies' undefined ≠ true)", () => {
    const holds = findComboHolds(
      rec([
        ['eslint', 'not-a-version'],
        ['eslint-config-next', '16.2.10'],
      ]),
      metaFor({ eslint: ESLINT_META }),
      NODE22,
      'npm',
    );
    expect(holds.size).toBe(0);
  });

  it('the fallback must install on the target runtime', () => {
    // Here 9.39.4 requires node >=20 but the target is node 18 → fall back to 9.38.0.
    const meta: RuntimeMeta = {
      latest: '10.6.0',
      constraints: { '9.38.0': '>=18', '9.39.4': '>=20', '10.6.0': '>=20' },
    };
    const holds = findComboHolds(
      rec([
        ['eslint', '10.6.0'],
        ['eslint-config-next', '16.2.10'],
      ]),
      metaFor({ eslint: meta }),
      { runtime: 'node', version: '18', source: '--node flag', explicit: true },
      'npm',
    );
    expect(holds.get('eslint')?.fallback).toBe('9.38.0');
  });

  it('reports the hold without a fallback when no known-good release exists', () => {
    const meta: RuntimeMeta = { latest: '10.6.0', constraints: { '10.0.0': '>=20', '10.6.0': '>=20' } };
    const holds = findComboHolds(
      rec([
        ['eslint', '10.6.0'],
        ['eslint-config-next', '16.2.10'],
      ]),
      metaFor({ eslint: meta }),
      NODE22,
      'npm',
    );
    expect(holds.get('eslint')).toMatchObject({ firstBad: '10.0.0' });
    expect(holds.get('eslint')?.fallback).toBeUndefined();
  });

  it('is npm-only for now (a pip plan never consults the registry)', () => {
    const holds = findComboHolds(
      rec([
        ['eslint', '10.6.0'],
        ['eslint-config-next', '16.2.10'],
      ]),
      metaFor({ eslint: ESLINT_META }),
      { runtime: 'python', version: '3.9', source: '--python flag', explicit: true },
      'PyPI',
    );
    expect(holds.size).toBe(0);
  });
});
