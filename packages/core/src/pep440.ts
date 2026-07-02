// Minimal PEP 440 evaluator for runtime-compatibility checks: orders PyPI release
// versions and evaluates specifier sets — both `Requires-Python` (">=3.10",
// "!=3.0.*,>=2.7") and requirements.txt ranges (">=0.30", "~=1.4") use the same
// grammar. In-house on purpose (zero-dep core, cf. cvss.ts / semver.ts). Skips
// exotica (`===`, local versions as specifiers); anything unparseable yields
// `undefined`, which callers MUST treat as "compatible" — silence over false alarms.

export interface Pep440 {
  epoch: number;
  release: number[];
  /** Pre-release phase + number: ["a"|"b"|"rc", N]. */
  pre?: [string, number];
  post?: number;
  dev?: number;
}

const VERSION_RE = new RegExp(
  '^v?' +
    '(?:(\\d+)!)?' + // epoch
    '(\\d+(?:\\.\\d+)*)' + // release
    '(?:[._-]?(a|alpha|b|beta|c|rc|pre|preview)[._-]?(\\d*))?' + // pre
    '(?:(?:-(\\d+))|(?:[._-]?(?:post|rev|r)[._-]?(\\d*)))?' + // post
    '(?:[._-]?dev[._-]?(\\d*))?' + // dev
    '(?:\\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$', // local (parsed, ignored for ordering)
  'i',
);

const PRE_NORMALIZE: Record<string, string> = {
  a: 'a',
  alpha: 'a',
  b: 'b',
  beta: 'b',
  c: 'rc',
  rc: 'rc',
  pre: 'rc',
  preview: 'rc',
};

export function parsePep440(s: string): Pep440 | undefined {
  const m = s.trim().match(VERSION_RE);
  if (!m) return undefined;
  const out: Pep440 = {
    epoch: m[1] ? Number(m[1]) : 0,
    release: m[2].split('.').map(Number),
  };
  if (m[3]) out.pre = [PRE_NORMALIZE[m[3].toLowerCase()], m[4] ? Number(m[4]) : 0];
  if (m[5] !== undefined) out.post = Number(m[5]);
  else if (m[6] !== undefined) out.post = m[6] ? Number(m[6]) : 0;
  if (m[7] !== undefined) out.dev = m[7] ? Number(m[7]) : 0;
  return out;
}

export function isPrereleasePep440(v: Pep440): boolean {
  return v.pre !== undefined || v.dev !== undefined;
}

function cmpRelease(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

const PRE_ORDER: Record<string, number> = { a: 0, b: 1, rc: 2 };

/**
 * PEP 440 ordering (mirrors packaging's key): within one release,
 * X.devN < X.aN < X.bN < X.rcN < X < X.postN.
 */
export function comparePep440(a: Pep440, b: Pep440): number {
  if (a.epoch !== b.epoch) return a.epoch - b.epoch;
  const r = cmpRelease(a.release, b.release);
  if (r !== 0) return r;
  // pre segment: dev-only (< everything) < pre < final
  const preKey = (v: Pep440): [number, number, number] => {
    if (v.pre) return [0, PRE_ORDER[v.pre[0]], v.pre[1]];
    if (v.post === undefined && v.dev !== undefined) return [-1, 0, 0]; // bare .devN
    return [1, 0, 0]; // final or post
  };
  const [ap, bp] = [preKey(a), preKey(b)];
  for (let i = 0; i < 3; i++) if (ap[i] !== bp[i]) return ap[i] - bp[i];
  const postKey = (v: Pep440) => (v.post === undefined ? -1 : v.post);
  if (postKey(a) !== postKey(b)) return postKey(a) - postKey(b);
  const devKey = (v: Pep440) => (v.dev === undefined ? Infinity : v.dev);
  const d = devKey(a) - devKey(b);
  return d === 0 || Number.isNaN(d) ? 0 : d;
}

// ---------------------------------------------------------------------------
// Specifier sets ("!=3.0.*,>=2.7"). Atom grammar: == != >= <= > < ~= plus `.*`
// wildcards on ==/!=. Unparseable atoms are skipped: extra constraints can only
// narrow, so a `false` from parseable atoms stays correct, and skipping keeps
// `true` on the never-false-alarm side.
// ---------------------------------------------------------------------------

interface Atom {
  op: string;
  value: string;
  wildcard: boolean;
}

function parseAtoms(specifiers: string): { atoms: Atom[]; unparseable: boolean } {
  const atoms: Atom[] = [];
  let unparseable = false;
  for (const raw of specifiers.split(',')) {
    const s = raw.trim();
    if (s === '') continue;
    const m = s.match(/^(===|==|!=|>=|<=|~=|>|<)\s*(.+)$/);
    if (!m || m[1] === '===') {
      unparseable = true;
      continue;
    }
    const wildcard = m[2].endsWith('.*');
    atoms.push({ op: m[1], value: wildcard ? m[2].slice(0, -2) : m[2], wildcard });
  }
  return { atoms, unparseable };
}

/** Does `version`'s release start with the wildcard prefix (e.g. "3.9" matches 3.9.7)? */
function prefixMatch(version: Pep440, prefix: Pep440): boolean {
  if (version.epoch !== prefix.epoch) return false;
  return prefix.release.every((seg, i) => (version.release[i] ?? 0) === seg);
}

function atomAdmits(atom: Atom, v: Pep440): boolean | undefined {
  const spec = parsePep440(atom.value);
  if (!spec) return undefined;
  if (atom.wildcard) {
    if (atom.op === '==') return prefixMatch(v, spec);
    if (atom.op === '!=') return !prefixMatch(v, spec);
    return undefined;
  }
  const c = comparePep440(v, spec);
  switch (atom.op) {
    case '==':
      return c === 0;
    case '!=':
      return c !== 0;
    case '>=':
      return c >= 0;
    case '<=':
      return c <= 0;
    case '>':
      return c > 0;
    case '<':
      return c < 0;
    case '~=': {
      // ~=X.Y.Z  ==>  >=X.Y.Z and ==X.Y.*  (needs at least two release segments)
      if (spec.release.length < 2) return undefined;
      const ceilingPrefix: Pep440 = { epoch: spec.epoch, release: spec.release.slice(0, -1) };
      return c >= 0 && prefixMatch(v, ceilingPrefix);
    }
    default:
      return undefined;
  }
}

/**
 * Does `version` satisfy the specifier set? `undefined` only when nothing was
 * evaluable — a definite `false` from parseable atoms is trusted even if other
 * atoms were skipped (they could only exclude more).
 */
export function specifierAdmits(specifiers: string, version: string): boolean | undefined {
  const v = parsePep440(version);
  if (!v) return undefined;
  const { atoms, unparseable } = parseAtoms(specifiers);
  let sawEvaluable = false;
  for (const atom of atoms) {
    const r = atomAdmits(atom, v);
    if (r === false) return false;
    if (r === true) sawEvaluable = true;
  }
  if (!sawEvaluable && (unparseable || atoms.length === 0)) return undefined;
  return true;
}

// --- series evaluation (interval arithmetic on release tuples) --------------

interface RBound {
  rel: number[];
  inclusive: boolean;
}

interface RInterval {
  lo: RBound | null;
  hi: RBound | null;
}

function bump(rel: number[]): number[] {
  const out = rel.slice();
  out[out.length - 1] += 1;
  return out;
}

function rMaxLo(a: RBound | null, b: RBound | null): RBound | null {
  if (!a) return b;
  if (!b) return a;
  const c = cmpRelease(a.rel, b.rel);
  if (c !== 0) return c > 0 ? a : b;
  return a.inclusive && b.inclusive ? a : { rel: a.rel, inclusive: false };
}

function rMinHi(a: RBound | null, b: RBound | null): RBound | null {
  if (!a) return b;
  if (!b) return a;
  const c = cmpRelease(a.rel, b.rel);
  if (c !== 0) return c < 0 ? a : b;
  return a.inclusive && b.inclusive ? a : { rel: a.rel, inclusive: false };
}

function rEmpty(iv: RInterval): boolean {
  if (!iv.lo || !iv.hi) return false;
  const c = cmpRelease(iv.lo.rel, iv.hi.rel);
  if (c > 0) return true;
  if (c === 0) return !(iv.lo.inclusive && iv.hi.inclusive);
  return false;
}

function rContains(outer: RInterval, inner: RInterval): boolean {
  const loOk =
    !outer.lo ||
    (inner.lo !== null &&
      (cmpRelease(outer.lo.rel, inner.lo.rel) < 0 ||
        (cmpRelease(outer.lo.rel, inner.lo.rel) === 0 && (outer.lo.inclusive || !inner.lo.inclusive))));
  const hiOk =
    !outer.hi ||
    (inner.hi !== null &&
      (cmpRelease(outer.hi.rel, inner.hi.rel) > 0 ||
        (cmpRelease(outer.hi.rel, inner.hi.rel) === 0 && (outer.hi.inclusive || !inner.hi.inclusive))));
  return loOk && hiOk;
}

/**
 * Is any version of the target series admitted by the specifier set? The target is a
 * (possibly partial) release like "3.9" = the series [3.9, 3.10). Interval arithmetic
 * on release tuples — exact for the specifier shapes seen in Requires-Python. `!=`
 * holes only force `false` when they cover the whole remaining interval.
 * `undefined` = cannot tell -> compatible.
 */
export function specifierAdmitsSeries(specifiers: string, target: string): boolean | undefined {
  const t = parsePep440(target);
  if (!t || t.pre || t.post !== undefined || t.dev !== undefined) return undefined;
  let iv: RInterval = {
    lo: { rel: t.release, inclusive: true },
    hi: { rel: bump(t.release), inclusive: false },
  };
  const holes: RInterval[] = [];
  const { atoms, unparseable } = parseAtoms(specifiers);
  let sawEvaluable = false;
  for (const atom of atoms) {
    const spec = parsePep440(atom.value);
    if (!spec || spec.pre || spec.dev !== undefined) continue; // skip: can only widen
    const rel = spec.release;
    sawEvaluable = true;
    switch (atom.op) {
      case '>=':
        iv = { lo: rMaxLo(iv.lo, { rel, inclusive: true }), hi: iv.hi };
        break;
      case '>':
        iv = { lo: rMaxLo(iv.lo, { rel, inclusive: false }), hi: iv.hi };
        break;
      case '<=':
        iv = { lo: iv.lo, hi: rMinHi(iv.hi, { rel, inclusive: true }) };
        break;
      case '<':
        iv = { lo: iv.lo, hi: rMinHi(iv.hi, { rel, inclusive: false }) };
        break;
      case '==':
        if (atom.wildcard) {
          iv = {
            lo: rMaxLo(iv.lo, { rel, inclusive: true }),
            hi: rMinHi(iv.hi, { rel: bump(rel), inclusive: false }),
          };
        } else {
          iv = {
            lo: rMaxLo(iv.lo, { rel, inclusive: true }),
            hi: rMinHi(iv.hi, { rel, inclusive: true }),
          };
        }
        break;
      case '!=':
        holes.push(
          atom.wildcard
            ? { lo: { rel, inclusive: true }, hi: { rel: bump(rel), inclusive: false } }
            : { lo: { rel, inclusive: true }, hi: { rel, inclusive: true } },
        );
        break;
      case '~=': {
        if (rel.length < 2) {
          sawEvaluable = false;
          continue;
        }
        iv = {
          lo: rMaxLo(iv.lo, { rel, inclusive: true }),
          hi: rMinHi(iv.hi, { rel: bump(rel.slice(0, -1)), inclusive: false }),
        };
        break;
      }
      default:
        continue;
    }
  }
  if (rEmpty(iv)) return false;
  if (holes.some((h) => rContains(h, iv))) return false;
  if (!sawEvaluable && (unparseable || atoms.length === 0)) return undefined;
  return true;
}
