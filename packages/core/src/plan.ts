import { renderDependabot, renderManifest, trimBoundary } from './artifacts';
import { findComboHolds } from './combos';
import { FRAMEWORK_SETS, lockstepFor, presentFrameworks } from './lockstep';
import { fetchVulns } from './osv';
import { computeRuntimeCompat } from './runtime-compat';
import { fetchRuntimeMetaAll } from './runtimes';
import type { Ecosystem, LockstepInfo, RuntimeTarget, Vuln } from './types';
import { runtimeLabel } from './verdict';

// `preflight plan` — the design-phase mode: given the runtime a new project will run
// on and the packages it intends to use, recommend the newest versions that actually
// install there and generate the guardrails (manifest floors + a dependabot.yml whose
// ignore rules stop the auto-updater at each compatibility boundary). This is the
// codified version of the incident where a merged floor bump was uninstallable on the
// dev machine and the ignore rules had to be reverse-engineered by hand.

export interface PlanRequest {
  ecosystem: Ecosystem;
  packages: string[];
  dev?: string[];
  target: RuntimeTarget;
  /** Seed a framework's lockstep set (FRAMEWORK_SETS name, case-insensitive), npm only. */
  framework?: string;
}

export interface PackagePlan {
  name: string;
  dev: boolean;
  latest?: string;
  /** Newest version that installs on the target (= latest when nothing dropped it). */
  recommended?: string;
  /** Manifest range expression, e.g. ">=0.39.0,<0.40" or "^2.4.1". */
  floor?: string;
  /** True when the latest release dropped the target — the floor is capped below it. */
  capped: boolean;
  /** The constraint that excludes the target (e.g. ">=3.10"), when capped. */
  constraint?: string;
  /** Lowest version that dropped the target — the auto-updater ignore boundary. */
  firstIncompatible?: string;
  lockstep: LockstepInfo;
  /** Known advisories against the recommended version (surfaced, not auto-stepped). */
  vulns: Vuln[];
  /** Set when a known-bad pair (combos.ts) held this package below its latest:
   * newer versions break beside `with`, so dependabot must ignore `firstBad`+. */
  heldBack?: { with: string; firstBad: string; reason: string };
  note: string;
}

export interface LockstepAdvice {
  framework: string;
  tool: string;
  members: string[];
  prefixes: string[];
}

export interface Plan {
  ecosystem: Ecosystem;
  target: RuntimeTarget;
  packages: PackagePlan[];
  lockstepAdvice?: LockstepAdvice;
  artifacts: {
    manifest: { filename: string; content: string };
    dependabot: { filename: string; content: string };
  };
}

/** Case-insensitive FRAMEWORK_SETS lookup ("expo" -> the Expo set). */
export function frameworkSet(name: string): (typeof FRAMEWORK_SETS)[number] | undefined {
  const n = name.trim().toLowerCase();
  return FRAMEWORK_SETS.find((s) => s.framework.toLowerCase() === n);
}

const firstNum = (v: string) => Number(v.match(/\d+/)?.[0] ?? NaN);

/** The manifest range: newest-compatible as the floor, capped below the boundary when needed. */
function floorFor(
  ecosystem: Ecosystem,
  recommended: string,
  firstIncompatible: string | undefined,
  capped: boolean,
): string {
  if (ecosystem === 'PyPI') {
    return capped && firstIncompatible
      ? `>=${recommended},<${trimBoundary(firstIncompatible)}`
      : `>=${recommended}`;
  }
  // npm: a caret already stops at the next major; only cap explicitly when the
  // boundary sits inside the same major.
  if (capped && firstIncompatible && firstNum(firstIncompatible) <= firstNum(recommended)) {
    return `>=${recommended} <${firstIncompatible}`;
  }
  return `^${recommended}`;
}

export async function buildPlan(req: PlanRequest): Promise<Plan> {
  const { ecosystem, target } = req;
  const fw = req.framework ? frameworkSet(req.framework) : undefined;
  if (req.framework && !fw) {
    throw new Error(
      `Unknown framework "${req.framework}" — known: ${FRAMEWORK_SETS.map((s) => s.framework).join(', ')}`,
    );
  }

  const dev = new Set((req.dev ?? []).map((p) => p.trim()).filter(Boolean));
  const names: string[] = [];
  const seen = new Set<string>();
  for (const name of [...(fw?.exact ?? []), ...req.packages, ...dev]) {
    const n = name.trim();
    if (n && !seen.has(n)) {
      seen.add(n);
      names.push(n);
    }
  }
  if (names.length === 0) throw new Error('Nothing to plan — pass packages and/or --framework');

  const metaMap = await fetchRuntimeMetaAll(names, ecosystem);

  // Attribution context: the explicitly requested framework plus any whose anchor
  // package is among the planned names — `react` in a Next.js plan must not read
  // "coordinated by Expo" (#18).
  const frameworks = presentFrameworks(names);
  if (fw) frameworks.add(fw.framework);

  const packages: PackagePlan[] = names.map((name) => {
    const meta = metaMap.get(name) ?? { constraints: {} };
    const lockstep = lockstepFor(name, frameworks);
    const latest = meta.latest;
    // Range "" = "any version": the compat result then carries the boundary info;
    // undefined result = every release installs on the target.
    const compat = computeRuntimeCompat({ range: '' }, meta, target, ecosystem);
    const recommended = compat ? compat.maxCompatible : latest;
    const capped = Boolean(compat?.latestIncompatible);

    const notes: string[] = [];
    if (!latest && Object.keys(meta.constraints).length === 0) {
      notes.push('no registry metadata found — check the package name');
    } else if (!recommended) {
      notes.push(`no release installs on ${runtimeLabel(target)}`);
    } else if (capped && compat?.firstIncompatible) {
      const verb = target.runtime === 'python' ? 'requires Python' : 'declares engines node';
      notes.push(
        `${compat.firstIncompatible}+ ${verb} ${compat.constraint ?? 'a newer runtime'} — capped`,
      );
    } else {
      notes.push(`latest still supports ${runtimeLabel(target)} — no cap needed`);
    }
    if (lockstep.pinned) notes.push(`coordinated by ${lockstep.framework} — update via ${lockstep.tool}`);

    return {
      name,
      dev: dev.has(name),
      latest,
      recommended,
      floor: recommended ? floorFor(ecosystem, recommended, compat?.firstIncompatible, capped) : undefined,
      capped,
      constraint: capped ? compat?.constraint : undefined,
      firstIncompatible: capped ? compat?.firstIncompatible : undefined,
      lockstep,
      vulns: [],
      note: notes.join(' · '),
    };
  });

  // A pair can be individually fine yet broken together — a wrong upstream peer range
  // hides it from every metadata check (#31: eslint 10 × eslint-config-next 16). Hold
  // the subject back to the newest known-good release that installs on the target.
  const holds = findComboHolds(
    new Map(packages.map((p) => [p.name, p.recommended])),
    (n) => metaMap.get(n),
    target,
    ecosystem,
  );
  for (const p of packages) {
    const hold = holds.get(p.name);
    if (!hold) continue;
    const pair = `${hold.combo.with}@${hold.withVersion}`;
    if (hold.fallback) {
      p.recommended = hold.fallback;
      p.floor = floorFor(ecosystem, hold.fallback, hold.firstBad, true);
      p.heldBack = { with: pair, firstBad: hold.firstBad, reason: hold.combo.reason };
      p.note = `held back: ${hold.firstBad}+ breaks with ${pair} — ${hold.combo.reason}`;
      if (p.lockstep.pinned) p.note += ` · coordinated by ${p.lockstep.framework} — update via ${p.lockstep.tool}`;
    } else {
      // No safe fallback exists — warn loudly, but never downgrade blindly.
      p.note += ` · ⚠ known-bad pair with ${pair} (${hold.combo.reason}) — no compatible fallback found, review manually`;
    }
  }

  // OSV-check the recommended versions: a floor that pins straight onto a known CVE
  // should be visible in the plan (surfaced, not auto-stepped).
  const vulnMap = await fetchVulns(
    packages
      .filter((p) => p.recommended)
      .map((p) => ({ name: p.name, range: p.floor ?? '', version: p.recommended, dev: p.dev })),
    ecosystem,
  );
  for (const p of packages) {
    p.vulns = vulnMap.get(`${p.name}@${p.recommended}`) ?? [];
    if (p.vulns.length > 0) p.note += ` · ⚠ ${p.vulns.length} known advisory against ${p.recommended}`;
  }

  const plan: Plan = {
    ecosystem,
    target,
    packages,
    lockstepAdvice: fw
      ? { framework: fw.framework, tool: fw.tool, members: fw.exact, prefixes: fw.prefixes }
      : undefined,
    artifacts: {
      manifest: { filename: '', content: '' },
      dependabot: { filename: '', content: '' },
    },
  };
  plan.artifacts.manifest = renderManifest(plan);
  plan.artifacts.dependabot = renderDependabot(plan);
  return plan;
}
