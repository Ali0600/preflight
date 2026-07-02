// Minimal npm-semver evaluator for runtime-compatibility checks (engines ranges +
// dependency ranges). In-house on purpose: @preflight/core has zero runtime deps
// (cf. cvss.ts). Covers the grammar seen in real manifests/engines — comparators,
// caret, tilde, x-ranges, hyphen ranges, space=AND, `||`=OR. Anything it cannot
// parse yields `undefined`, which callers MUST treat as "compatible" — a missed
// warning is acceptable, a false alarm is not.

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  /** Dot-separated prerelease identifiers ("beta.1" -> ["beta","1"]); absent = release. */
  prerelease?: string[];
}

const VERSION_RE =
  /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$/;

/** Parse a full semver version ("1.2.3", "v1.2.3-beta.1+build"). Partials -> undefined. */
export function parseSemver(s: string): SemVer | undefined {
  const m = s.trim().match(VERSION_RE);
  if (!m) return undefined;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    ...(m[4] ? { prerelease: m[4].split('.') } : {}),
  };
}

export function isPrereleaseSemver(v: SemVer): boolean {
  return (v.prerelease?.length ?? 0) > 0;
}

function compareIds(a: string, b: string): number {
  const an = /^\d+$/.test(a);
  const bn = /^\d+$/.test(b);
  if (an && bn) return Number(a) - Number(b);
  if (an) return -1; // numeric identifiers sort before alphanumeric
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Standard semver precedence, including prerelease ordering (1.0.0-beta < 1.0.0). */
export function compareSemver(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  const ap = a.prerelease ?? [];
  const bp = b.prerelease ?? [];
  if (ap.length === 0 && bp.length === 0) return 0;
  if (ap.length === 0) return 1; // release > its prereleases
  if (bp.length === 0) return -1;
  for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
    if (ap[i] === undefined) return -1; // shorter prerelease sorts first
    if (bp[i] === undefined) return 1;
    const c = compareIds(ap[i], bp[i]);
    if (c !== 0) return c;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Ranges as intervals. Each `||` branch normalizes to one [lo, hi) interval
// (with inclusivity flags); AND within a branch is interval intersection.
// ---------------------------------------------------------------------------

interface Bound {
  v: SemVer;
  inclusive: boolean;
}

/** null bound = unbounded on that side. `empty` marks an unsatisfiable branch. */
interface Interval {
  lo: Bound | null;
  hi: Bound | null;
  empty?: boolean;
}

const ZERO: SemVer = { major: 0, minor: 0, patch: 0 };

function sv(major: number, minor = 0, patch = 0): SemVer {
  return { major, minor, patch };
}

/** Parse a possibly-partial version ("1", "1.2", "1.2.x", "*") -> filled parts + how many were given. */
function parsePartial(s: string): { parts: [number, number, number]; given: number } | undefined {
  const t = s.trim().replace(/^v/, '');
  if (t === '' || t === '*' || t.toLowerCase() === 'x') return { parts: [0, 0, 0], given: 0 };
  const m = t.match(/^(\d+)(?:\.(\d+|x|X|\*))?(?:\.(\d+|x|X|\*))?(?:-[0-9A-Za-z-.]+)?$/);
  if (!m) return undefined;
  const isNum = (p?: string) => p !== undefined && /^\d+$/.test(p);
  const major = Number(m[1]);
  if (!isNum(m[2])) return { parts: [major, 0, 0], given: 1 };
  const minor = Number(m[2]);
  if (!isNum(m[3])) return { parts: [major, minor, 0], given: 2 };
  return { parts: [major, minor, Number(m[3])], given: 3 };
}

/** The [lo, hi) interval covered by a bare (possibly partial) version: "1.2" -> [1.2.0, 1.3.0). */
function partialInterval(s: string): Interval | undefined {
  const p = parsePartial(s);
  if (!p) return undefined;
  const [ma, mi, pa] = p.parts;
  if (p.given === 0) return { lo: { v: ZERO, inclusive: true }, hi: null };
  if (p.given === 1)
    return { lo: { v: sv(ma), inclusive: true }, hi: { v: sv(ma + 1), inclusive: false } };
  if (p.given === 2)
    return { lo: { v: sv(ma, mi), inclusive: true }, hi: { v: sv(ma, mi + 1), inclusive: false } };
  const exact = sv(ma, mi, pa);
  return { lo: { v: exact, inclusive: true }, hi: { v: exact, inclusive: true } };
}

/** One comparator/pattern -> an interval, or undefined when unparseable. */
function comparatorInterval(raw: string): Interval | undefined {
  const s = raw.trim();
  if (s === '') return undefined;
  const opMatch = s.match(/^(>=|<=|>|<|=|\^|~)?\s*(.+)$/);
  if (!opMatch) return undefined;
  const op = opMatch[1] ?? '';
  const rest = opMatch[2];
  const p = parsePartial(rest);
  if (!p) return undefined;
  const [ma, mi, pa] = p.parts;
  const v = sv(ma, mi, pa);
  switch (op) {
    case '>=':
      return { lo: { v, inclusive: true }, hi: null };
    case '>':
      // ">1.2" means ">=1.3.0" for partials in node-semver; full versions are exclusive
      if (p.given === 1) return { lo: { v: sv(ma + 1), inclusive: true }, hi: null };
      if (p.given === 2) return { lo: { v: sv(ma, mi + 1), inclusive: true }, hi: null };
      return { lo: { v, inclusive: false }, hi: null };
    case '<=':
      // "<=1.2" means "<1.3.0" (the whole 1.2.x series is admitted)
      if (p.given === 1) return { lo: null, hi: { v: sv(ma + 1), inclusive: false } };
      if (p.given === 2) return { lo: null, hi: { v: sv(ma, mi + 1), inclusive: false } };
      return { lo: null, hi: { v, inclusive: true } };
    case '<':
      return { lo: null, hi: { v, inclusive: false } };
    case '^': {
      let hi: SemVer;
      if (ma > 0 || p.given === 1) hi = sv(ma + 1);
      else if (mi > 0 || p.given === 2) hi = sv(ma, mi + 1);
      else hi = sv(ma, mi, pa + 1);
      return { lo: { v, inclusive: true }, hi: { v: hi, inclusive: false } };
    }
    case '~': {
      const hi = p.given <= 1 ? sv(ma + 1) : sv(ma, mi + 1);
      return { lo: { v, inclusive: true }, hi: { v: hi, inclusive: false } };
    }
    default:
      // bare or "=": x-range semantics
      return partialInterval(rest);
  }
}

function maxLo(a: Bound | null, b: Bound | null): Bound | null {
  if (!a) return b;
  if (!b) return a;
  const c = compareSemver(a.v, b.v);
  if (c !== 0) return c > 0 ? a : b;
  return a.inclusive && b.inclusive ? a : { v: a.v, inclusive: false };
}

function minHi(a: Bound | null, b: Bound | null): Bound | null {
  if (!a) return b;
  if (!b) return a;
  const c = compareSemver(a.v, b.v);
  if (c !== 0) return c < 0 ? a : b;
  return a.inclusive && b.inclusive ? a : { v: a.v, inclusive: false };
}

function isEmpty(iv: Interval): boolean {
  if (iv.empty) return true;
  if (!iv.lo || !iv.hi) return false;
  const c = compareSemver(iv.lo.v, iv.hi.v);
  if (c > 0) return true;
  if (c === 0) return !(iv.lo.inclusive && iv.hi.inclusive);
  return false;
}

/** One `||` branch ("​>=1.2 <2" or "1.2 - 2.4" or "^1.7") -> interval. */
function branchInterval(branch: string): Interval | undefined {
  const b = branch.trim();
  if (b === '') return { lo: { v: ZERO, inclusive: true }, hi: null }; // "" / "*" = any
  const hyphen = b.split(/\s+-\s+/);
  if (hyphen.length === 2) {
    const lo = partialInterval(hyphen[0]);
    const hi = partialInterval(hyphen[1]);
    if (!lo || !hi) return undefined;
    return { lo: lo.lo, hi: hi.hi };
  }
  let acc: Interval = { lo: null, hi: null };
  for (const part of b.split(/\s+/)) {
    const iv = comparatorInterval(part);
    if (!iv) return undefined;
    acc = { lo: maxLo(acc.lo, iv.lo), hi: minHi(acc.hi, iv.hi) };
  }
  if (isEmpty(acc)) acc.empty = true;
  return acc;
}

function rangeIntervals(range: string): { intervals: Interval[]; unparseable: boolean } {
  const intervals: Interval[] = [];
  let unparseable = false;
  for (const branch of range.split('||')) {
    const iv = branchInterval(branch);
    if (iv) intervals.push(iv);
    else unparseable = true;
  }
  return { intervals, unparseable };
}

function within(v: SemVer, iv: Interval): boolean {
  if (isEmpty(iv)) return false;
  if (iv.lo) {
    const c = compareSemver(v, iv.lo.v);
    if (c < 0 || (c === 0 && !iv.lo.inclusive)) return false;
  }
  if (iv.hi) {
    const c = compareSemver(v, iv.hi.v);
    if (c > 0 || (c === 0 && !iv.hi.inclusive)) return false;
  }
  return true;
}

/**
 * Does `version` satisfy `range`? `undefined` when the version or the whole range is
 * unparseable, or when the parseable branches say "no" but an unparseable branch might
 * still admit it — callers treat `undefined` as satisfied (never false-alarm).
 */
export function satisfies(version: string, range: string): boolean | undefined {
  const v = parseSemver(version);
  if (!v) return undefined;
  const { intervals, unparseable } = rangeIntervals(range);
  if (intervals.some((iv) => within(v, iv))) return true;
  return unparseable || intervals.length === 0 ? undefined : false;
}

function intersects(a: Interval, b: Interval): boolean {
  if (isEmpty(a) || isEmpty(b)) return false;
  const lo = maxLo(a.lo, b.lo);
  const hi = minHi(a.hi, b.hi);
  return !isEmpty({ lo, hi });
}

/**
 * Is any version of the target series admitted by `range`? The target may be partial:
 * "18" = the whole [18.0.0, 19.0.0) series (so `engines: ">=18.17"` is compatible with
 * target "18" but not with target "18.2.0"). `undefined` = cannot tell -> compatible.
 */
export function rangeAdmitsSeries(range: string, target: string): boolean | undefined {
  const series = partialInterval(target);
  if (!series) return undefined;
  const { intervals, unparseable } = rangeIntervals(range);
  if (intervals.some((iv) => intersects(iv, series))) return true;
  return unparseable || intervals.length === 0 ? undefined : false;
}
