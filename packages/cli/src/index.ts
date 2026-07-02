#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import {
  analyze,
  detectRuntimes,
  evaluatePolicy,
  licenseRisk,
  loadPolicy,
  policyNeeds,
  runtimeLabel,
  setCacheEnabled,
  toCycloneDX,
  type Finding,
  type Report,
  type RuntimeName,
  type Verdict,
  type Violation,
} from '@preflight/core';
import { Command } from 'commander';
import pc from 'picocolors';

import { registerPlanCommand } from './plan';

const BADGE: Record<Verdict, (s: string) => string> = {
  malware: (s) => pc.bgRed(pc.white(pc.bold(` ${s} `))),
  cve: (s) => pc.bgRed(pc.white(` ${s} `)),
  incompatible: (s) => pc.bgBlue(pc.white(` ${s} `)),
  pinned: (s) => pc.bgYellow(pc.black(` ${s} `)),
  safe: (s) => pc.bgGreen(pc.black(` ${s} `)),
  stale: (s) => pc.bgMagenta(pc.white(` ${s} `)),
};

const LABEL: Record<Verdict, string> = {
  malware: 'MALWARE',
  cve: 'CVE',
  incompatible: 'INCOMPAT',
  pinned: 'PINNED',
  safe: 'SAFE',
  stale: 'STALE',
};
const ORDER: Record<Verdict, number> = {
  malware: 0,
  cve: 1,
  incompatible: 2,
  pinned: 3,
  stale: 4,
  safe: 5,
};

const byVerdict = (a: Finding, b: Finding) => ORDER[a.verdict] - ORDER[b.verdict];

function licenseTag(f: Finding): string {
  if (!f.license) return '';
  const risk = licenseRisk(f.license);
  const text = ` · ${f.license}`;
  if (risk === 'copyleft') return pc.yellow(text);
  if (risk === 'unknown') return pc.dim(`${text}?`);
  return pc.dim(text);
}

function printFinding(f: Finding): void {
  const badge = BADGE[f.verdict](LABEL[f.verdict].padEnd(8));
  const latest = f.latest && f.latest !== f.version ? pc.dim(` · latest ${f.latest}`) : '';
  console.log(
    `${badge}  ${pc.bold(f.name)}${pc.dim(`@${f.version ?? f.range}`)}${latest}${licenseTag(f)}`,
  );
  console.log(`          ${pc.dim(f.reason)}`);
  if (f.suspiciousName) {
    console.log(`          ${pc.yellow(`⚠ name resembles "${f.suspiciousName.similarTo}" — confirm it's intended`)}`);
  }
  if (f.installScript) {
    console.log(`          ${pc.yellow('⚙ runs an install script (code executes on npm install)')}`);
  }
  // Early warning: today's install works, but the newest release dropped the target —
  // the next auto-bump breaks. (When the verdict is already `incompatible`, the reason covers it.)
  if (f.runtimeCompat?.latestIncompatible && f.verdict !== 'incompatible') {
    const rc = f.runtimeCompat;
    const boundary = rc.firstIncompatible ? ` — add an auto-updater ignore for ${rc.firstIncompatible}+` : '';
    console.log(
      `          ${pc.yellow(`⏫ newest release drops ${runtimeLabel(rc.target)}${boundary}`)}`,
    );
  }
  if (f.health !== undefined) {
    const weak = f.healthChecks?.length
      ? pc.dim(` · weak: ${f.healthChecks.map((c) => c.name).join(', ')}`)
      : '';
    console.log(`          ${pc.dim(`OpenSSF health ${f.health.toFixed(1)}/10`)}${weak}`);
  }
}

function printReport(r: Report): void {
  const direct = r.findings.filter((f) => f.direct !== false);
  const transitive = r.findings.filter((f) => f.direct === false);
  const transitiveVulns = transitive.filter((f) => f.vulns.length > 0);

  console.log();
  console.log(pc.bold(`Preflight — ${r.path}`));
  const counts = transitive.length
    ? `${r.total} deps (${direct.length} direct · ${transitive.length} transitive)`
    : `${r.total} deps`;
  const malware = r.summary.malware > 0 ? `${r.summary.malware} malware · ` : '';
  const incompat = r.summary.incompatible > 0 ? `${r.summary.incompatible} incompatible · ` : '';
  console.log(
    pc.dim(
      `${counts} · ${malware}${r.summary.cve} CVE · ${incompat}${r.summary.pinned} pinned · ${r.summary.stale} stale · ${r.summary.safe} safe`,
    ),
  );
  if (r.runtimeTarget) {
    console.log(pc.dim(`target runtime: ${runtimeLabel(r.runtimeTarget, true)}`));
  }
  const scripts = r.findings.filter((f) => f.installScript).length;
  const suspicious = r.findings.filter((f) => f.suspiciousName).length;
  if (scripts > 0 || suspicious > 0) {
    const bits = [
      scripts > 0 ? `${scripts} run install scripts` : '',
      suspicious > 0 ? pc.yellow(`${suspicious} suspicious name(s)`) : '',
    ].filter(Boolean);
    console.log(pc.dim(`supply-chain: ${bits.join(' · ')}`));
  }
  console.log();
  for (const f of [...direct].sort(byVerdict)) printFinding(f);
  // Transitive deps are too numerous to list in full; surface only the ones that carry a CVE.
  if (transitiveVulns.length > 0) {
    console.log();
    console.log(pc.bold(`Transitive dependencies with CVEs (${transitiveVulns.length})`));
    for (const f of [...transitiveVulns].sort(byVerdict)) printFinding(f);
  }
  console.log();
}

function printPolicy(file: string, violations: Violation[]): void {
  // To stderr, so it never pollutes --json / --sbom stdout.
  if (violations.length === 0) {
    console.error(pc.green(`\n✓ policy ok (${file})`));
    return;
  }
  console.error(pc.red(`\n✗ ${violations.length} policy violation(s) (${file}):`));
  for (const v of violations) console.error(pc.red(`  · ${v.rule}: ${v.dep} — ${v.detail}`));
}

const program = new Command();

program
  .name('preflight')
  .description('Pre-flight a dependency manifest: CVEs, framework-lockstep, auto-update safety.')
  .version('0.1.0');

program
  .command('check')
  .argument('[path]', 'path to package.json or requirements*.txt', 'package.json')
  .option('--json', 'output the raw report as JSON')
  .option('--sbom [file]', 'emit a CycloneDX SBOM (to <file>, or stdout if omitted)')
  .option('--latest', "fetch each dep's latest version + last-publish date (enables 'stale')")
  .option('--health', "fetch each dep's OpenSSF Scorecard from deps.dev")
  .option(
    '--node <version>',
    'target Node runtime the manifest must install on ("18" = the whole 18.x series)',
  )
  .option(
    '--python <version>',
    'target Python runtime the manifest must install on ("3.9" = the whole 3.9.x series)',
  )
  .option('--policy [file]', 'gate the run against a policy file (default ./preflight.config.json)')
  .option('--no-cache', 'bypass the on-disk 24h cache (.preflight-cache/)')
  .action(
    async (
      path: string,
      opts: {
        json?: boolean;
        sbom?: boolean | string;
        latest?: boolean;
        health?: boolean;
        node?: string;
        python?: string;
        policy?: boolean | string;
        cache?: boolean;
      },
    ) => {
      if (opts.cache === false) setCacheEnabled(false);
      // Load the policy first — its rules decide whether we need latest-version / health data.
      const policyFile =
        opts.policy === undefined
          ? undefined
          : typeof opts.policy === 'string'
            ? opts.policy
            : 'preflight.config.json';
      const policy = policyFile ? loadPolicy(policyFile) : undefined;
      const need = policy ? policyNeeds(policy) : { latest: false, health: false, runtime: false };
      // Target runtimes, highest precedence first: flags > config `runtimes` (the default
      // config file counts even without --policy) > version files beside the manifest.
      const configRuntimes = (policy ?? loadPolicy('preflight.config.json')).runtimes ?? {};
      const runtimes = detectRuntimes(dirname(path));
      for (const runtime of ['node', 'python'] as RuntimeName[]) {
        const flag = opts[runtime];
        if (flag) {
          runtimes[runtime] = { runtime, version: flag, source: `--${runtime} flag`, explicit: true };
        } else if (configRuntimes[runtime]) {
          runtimes[runtime] = {
            runtime,
            version: configRuntimes[runtime]!,
            source: 'preflight.config.json',
            explicit: true,
          };
        }
      }
      let report: Report;
      try {
        report = await analyze(path, {
          latest: opts.latest || need.latest,
          health: opts.health || need.health,
          runtimes,
        });
      } catch (err) {
        console.error(pc.red(`preflight: ${(err as Error).message}`));
        process.exitCode = 1;
        return;
      }
      if (opts.sbom !== undefined) {
        const sbom = JSON.stringify(toCycloneDX(report), null, 2);
        if (typeof opts.sbom === 'string') {
          writeFileSync(opts.sbom, sbom);
          console.log(pc.dim(`Wrote CycloneDX SBOM → ${opts.sbom}`));
        } else {
          console.log(sbom);
        }
      } else if (opts.json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        printReport(report);
      }
      if (policy && policyFile) {
        const { violations, fail } = evaluatePolicy(report.findings, policy);
        printPolicy(policyFile, violations);
        if (fail) process.exitCode = 1;
      } else {
        // Default gate: non-zero exit when any dependency carries a CVE or is malicious —
        // or cannot install on an *explicitly* declared runtime (auto-detected targets only
        // warn: a build that was green yesterday shouldn't fail because a .nvmrc was noticed).
        const explicitIncompat =
          (report.runtimeTarget?.explicit ?? false) && report.summary.incompatible > 0;
        if (report.summary.cve > 0 || report.summary.malware > 0 || explicitIncompat) {
          process.exitCode = 1;
        }
      }
    },
  );

registerPlanCommand(program);

await program.parseAsync();
