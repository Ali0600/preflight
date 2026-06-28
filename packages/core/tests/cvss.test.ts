import { describe, expect, it } from 'vitest';

import { cvssV3Severity } from '../src/cvss';

describe('cvssV3Severity', () => {
  it('maps a max-impact vector to critical (9.8)', () => {
    expect(cvssV3Severity('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe('critical');
  });

  it('maps a high-complexity confidentiality-only vector to medium (5.9)', () => {
    expect(cvssV3Severity('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N')).toBe('medium');
  });

  it('handles a scope-changed (reflected-XSS) vector → medium (6.1)', () => {
    expect(cvssV3Severity('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe('medium');
  });

  it('returns undefined for non-v3 or malformed vectors', () => {
    expect(cvssV3Severity('CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeUndefined();
    expect(cvssV3Severity('not-a-vector')).toBeUndefined();
    expect(cvssV3Severity('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeUndefined();
  });
});
