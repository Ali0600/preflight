import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import {
  buildPlan,
  runtimeLabel,
  setCacheEnabled,
  type Ecosystem,
  type Plan,
  type PackagePlan,
} from '@preflight/core';
import type { Command } from 'commander';
import pc from 'picocolors';

// `preflight plan` — design-phase mode: pick a runtime (+ optionally a framework),
// list the packages you intend to use, get the newest versions that actually install
// there plus generated guardrails (manifest floors + dependabot ignores).

/** One table row: recommended pin, cap marker, and the why. Pure — unit-tested. */
export function renderPlanRow(p: PackagePlan): string {
  const version = p.recommended ?? '—';
  const behind =
    p.capped && p.latest && p.latest !== p.recommended ? ` (latest ${p.latest} incompatible)` : '';
  const head = `${p.name}@${version}${behind}${p.dev ? ' · dev' : ''}`;
  return `${head}\n    ${p.note}`;
}

/** The full human plan output (table + artifacts). Pure — unit-tested. */
export function renderPlanText(plan: Plan): string {
  const lines: string[] = [];
  const capped = plan.packages.filter((p) => p.capped).length;
  lines.push(`Plan — ${plan.packages.length} package(s) on ${runtimeLabel(plan.target)}`);
  if (capped > 0) lines.push(`${capped} capped below their latest to stay installable`);
  lines.push('');
  for (const p of plan.packages) lines.push(renderPlanRow(p), '');
  if (plan.lockstepAdvice) {
    const a = plan.lockstepAdvice;
    lines.push(
      `${a.framework} lockstep: ${a.members.join(', ')} (+ ${a.prefixes.join(', ')} packages)`,
      `    versions are coordinated by the framework — update with \`${a.tool}\`,`,
      `    never per-package; the generated dependabot.yml ignores the whole set.`,
      '',
    );
  }
  for (const a of [plan.artifacts.manifest, plan.artifacts.dependabot]) {
    lines.push(`── ${a.filename} ${'─'.repeat(Math.max(4, 56 - a.filename.length))}`, a.content.trimEnd(), '');
  }
  return lines.join('\n');
}

interface PlanOpts {
  node?: string;
  python?: string;
  framework?: string;
  dev?: string[];
  json?: boolean;
  write?: boolean | string;
  force?: boolean;
  cache?: boolean;
}

/** Flatten a variadic option's values, tolerating comma-separated lists: ['a,b','c'] → ['a','b','c']. */
export function splitPackages(values: string[] = []): string[] {
  return values
    .flatMap((v) => v.split(','))
    .map((s) => s.trim())
    .filter(Boolean);
}

export function registerPlanCommand(program: Command): void {
  program
    .command('plan')
    .description(
      'Design-phase mode: recommend versions that install on a target runtime and generate manifest + dependabot guardrails.',
    )
    .argument('[packages...]', 'packages the new project will use')
    .option('--node <version>', 'target Node runtime ("18" = the whole 18.x series) — implies npm')
    .option('--python <version>', 'target Python runtime (e.g. "3.9") — implies pip')
    .option('--framework <name>', 'seed a framework lockstep set (e.g. expo, next.js) — npm only')
    // Variadic: consumes every following package until the next --flag (commas also work).
    .option('--dev <packages...>', 'dev-only packages (list them after the flag)')
    .option('--json', 'output the raw plan as JSON')
    .option('--write [dir]', 'write the generated files into <dir> (default .)')
    .option('--force', 'overwrite existing files with --write')
    .option('--no-cache', 'bypass the on-disk 24h cache (.preflight-cache/)')
    .action(async (packages: string[], opts: PlanOpts) => {
      if (opts.cache === false) setCacheEnabled(false);
      if (Boolean(opts.node) === Boolean(opts.python)) {
        console.error(pc.red('preflight plan: pass exactly one of --node or --python'));
        process.exitCode = 1;
        return;
      }
      const ecosystem: Ecosystem = opts.node ? 'npm' : 'PyPI';
      if (opts.framework && ecosystem !== 'npm') {
        console.error(pc.red('preflight plan: --framework applies to npm (use --node)'));
        process.exitCode = 1;
        return;
      }
      const runtime = opts.node ? ('node' as const) : ('python' as const);
      try {
        const plan = await buildPlan({
          ecosystem,
          packages,
          dev: splitPackages(opts.dev),
          framework: opts.framework,
          target: {
            runtime,
            version: (opts.node ?? opts.python)!,
            source: `--${runtime} flag`,
            explicit: true,
          },
        });
        if (opts.json) {
          console.log(JSON.stringify(plan, null, 2));
        } else {
          console.log(renderPlanText(plan));
        }
        if (opts.write !== undefined) {
          const dir = typeof opts.write === 'string' ? opts.write : '.';
          writeArtifacts(plan, dir, Boolean(opts.force));
        }
      } catch (err) {
        console.error(pc.red(`preflight plan: ${(err as Error).message}`));
        process.exitCode = 1;
      }
    });
}

function writeArtifacts(plan: Plan, dir: string, force: boolean): void {
  for (const a of [plan.artifacts.manifest, plan.artifacts.dependabot]) {
    const path = join(dir, a.filename);
    if (existsSync(path) && !force) {
      console.error(pc.yellow(`skipped ${path} — already exists (use --force to overwrite)`));
      continue;
    }
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, a.content);
    console.error(pc.green(`wrote ${path}`));
  }
}
