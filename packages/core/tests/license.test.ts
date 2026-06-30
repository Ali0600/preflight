import { describe, expect, it } from 'vitest';

import { licenseRisk } from '../src/license';

describe('licenseRisk', () => {
  it('buckets permissive licenses', () => {
    expect(licenseRisk('MIT')).toBe('permissive');
    expect(licenseRisk('Apache-2.0')).toBe('permissive');
    expect(licenseRisk('BSD-3-Clause')).toBe('permissive');
    expect(licenseRisk('ISC')).toBe('permissive');
  });

  it('flags copyleft licenses', () => {
    expect(licenseRisk('GPL-3.0')).toBe('copyleft');
    expect(licenseRisk('AGPL-3.0-only')).toBe('copyleft');
    expect(licenseRisk('LGPL-2.1')).toBe('copyleft');
    expect(licenseRisk('MPL-2.0')).toBe('copyleft');
  });

  it('treats missing or unrecognized as unknown', () => {
    expect(licenseRisk(undefined)).toBe('unknown');
    expect(licenseRisk('SEE LICENSE IN FILE')).toBe('unknown');
    expect(licenseRisk('Proprietary')).toBe('unknown');
  });
});
