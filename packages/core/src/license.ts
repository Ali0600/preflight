export type LicenseRisk = 'permissive' | 'copyleft' | 'unknown';

// Coarse license-risk buckets. Copyleft (GPL/AGPL/LGPL/…) carries obligations that often matter for
// proprietary distribution; unknown/missing is its own risk (you can't comply with what you can't see).
const COPYLEFT = /\b(a?gpl|lgpl|mpl|epl|cddl|osl|eupl|cpal|sleepycat)\b/i;
const PERMISSIVE = /\b(mit|apache|bsd|isc|0bsd|unlicense|wtfpl|zlib|cc0|python|psf)\b/i;

/** Bucket a license id/string into permissive / copyleft / unknown. */
export function licenseRisk(license?: string): LicenseRisk {
  if (!license) return 'unknown';
  if (COPYLEFT.test(license)) return 'copyleft';
  if (PERMISSIVE.test(license)) return 'permissive';
  return 'unknown';
}
