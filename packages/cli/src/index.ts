#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname } from 'node:path';

import {
  analyze,
  detectRuntimes,
  evaluatePolicy,
  licenseRisk,
  loadPolicy,
  meetsVulnLevel,
  policyNeeds,
  runtimeLabel,
  setCacheEnabled,
  toCycloneDX,
  VERDICT_LABEL,
  VERDICT_ORDER,
  type DataSource,
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
  deprecated: (s) => pc.bgYellow(pc.black(` ${s} `)),
  pinned: (s) => pc.bgYellow(pc.black(` ${s} `)),
  safe: (s) => pc.bgGreen(pc.black(` ${s} `)),
  stale: (s) => pc.bgMagenta(pc.white(` ${s} `)),
};

// Badge column width tracks the longest shared label so rows stay aligned as verdicts grow.
const BADGE_PAD = Math.max(...Object.values(VERDICT_LABEL).map((l) => l.length));

// Labels + worst-first ordering are shared from core (VERDICT_LABEL / VERDICT_ORDER) so every
// surface agrees; only the colours above are CLI-specific.
const byVerdict = (a: Finding, b: Finding) => VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict];

/** "1234567" -> "1.2M" — weekly download counts read better rounded. */
function fmtCount(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(n);
}

/** The typosquat warning, with download counts behind it when they were reachable: a lookalike
 * nobody installs next to a target everyone installs is the classic signature — and a flagged
 * name that is itself heavily used is probably a legitimate package. */
function squatLine(s: NonNullable<Finding['suspiciousName']>): string {
  let line = `⚠ name resembles "${s.similarTo}"`;
  if (s.downloadsPerWeek !== undefined && s.targetDownloadsPerWeek !== undefined) {
    line += ` (${fmtCount(s.targetDownloadsPerWeek)} dl/wk) — this package: ${fmtCount(s.downloadsPerWeek)} dl/wk`;
    if (s.downloadsPerWeek < 1_000 && s.targetDownloadsPerWeek >= 100_000) {
      line += ' — classic typosquat signature';
    } else if (s.downloadsPerWeek >= 100_000) {
      line += ' — both widely used, likely legitimate';
    }
  }
  return `${line} — confirm it's intended`;
}

function licenseTag(f: Finding): string {
  if (!f.license) return '';
  const risk = licenseRisk(f.license);
  const text = ` · ${f.license}`;
  if (risk === 'copyleft') return pc.yellow(text);
  if (risk === 'unknown') return pc.dim(`${text}?`);
  return pc.dim(text);
}

function printFinding(f: Finding): void {
  const badge = BADGE[f.verdict](VERDICT_LABEL[f.verdict].padEnd(BADGE_PAD));
  const latest = f.latest && f.latest !== f.version ? pc.dim(` · latest ${f.latest}`) : '';
  console.log(
    `${badge}  ${pc.bold(f.name)}${pc.dim(`@${f.version ?? f.range}`)}${latest}${licenseTag(f)}`,
  );
  console.log(`          ${pc.dim(f.reason)}`);
  if (f.suspiciousName) {
    console.log(`          ${pc.yellow(squatLine(f.suspiciousName))}`);
  }
  if (f.installScript) {
    console.log(`          ${pc.yellow('⚙ runs an install script (code executes on npm install)')}`);
  }
  // A worse verdict (cve/incompatible) can outrank `deprecated` — still announce the notice.
  if (f.deprecated && f.verdict !== 'deprecated') {
    console.log(`          ${pc.yellow(`⚰ deprecated upstream: ${f.deprecated}`)}`);
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
  if (f.health !== undefined || f.downloadsPerWeek !== undefined) {
    const parts = [
      f.health !== undefined ? `OpenSSF health ${f.health.toFixed(1)}/10` : undefined,
      f.downloadsPerWeek !== undefined ? `≈${fmtCount(f.downloadsPerWeek)} dl/wk` : undefined,
    ].filter(Boolean);
    const weak = f.healthChecks?.length
      ? pc.dim(` · weak: ${f.healthChecks.map((c) => c.name).join(', ')}`)
      : '';
    console.log(`          ${pc.dim(parts.join(' · '))}${weak}`);
  }
  // Build provenance (npm Sigstore / PyPI PEP 740) — only fetched under --health. Most packages
  // ship none, so presence is the notable signal; "verified" is deps.dev's signature check.
  if (f.provenance) {
    const src = f.provenance.sourceRepository ? ` from ${f.provenance.sourceRepository}` : '';
    console.log(
      f.provenance.verified
        ? `          ${pc.green(`🔏 verified build provenance${src}`)}`
        : `          ${pc.dim(`🔏 build attestation present (unverified)${src}`)}`,
    );
  }
}

/** The transparency ledger: which data sources ran this scan and what each returned. Printed so a
 * clean result still shows *what was checked*, not just "nothing found". */
function printSources(sources: Report['sources']): void {
  if (!sources || sources.length === 0) return;
  const icon = (s: DataSource['status']): string =>
    s === 'ok' ? pc.green('✓') : s === 'degraded' ? pc.yellow('⚠') : pc.dim('·');
  console.log(pc.bold('Data sources'));
  for (const s of sources) {
    const line = `  ${icon(s.status)} ${s.name} — ${s.detail}`;
    console.log(s.status === 'skipped' ? pc.dim(line) : line);
  }
  console.log();
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
  const deprecated = r.summary.deprecated > 0 ? `${r.summary.deprecated} deprecated · ` : '';
  console.log(
    pc.dim(
      `${counts} · ${malware}${r.summary.cve} CVE · ${incompat}${deprecated}${r.summary.pinned} pinned · ${r.summary.stale} stale · ${r.summary.safe} safe`,
    ),
  );
  if (r.runtimeTarget) {
    console.log(pc.dim(`target runtime: ${runtimeLabel(r.runtimeTarget, true)}`));
    // The interpreter itself can be the risk: an EOL runtime gets no security fixes, and no
    // dependency-level verdict can say so. Loud when dead, a heads-up when <90 days out.
    if (r.runtimeEol?.isEol) {
      console.log(
        pc.red(
          `✖ ${runtimeLabel(r.runtimeTarget)} reached end-of-life${r.runtimeEol.eol ? ` on ${r.runtimeEol.eol}` : ''} — no security fixes (endoflife.date)`,
        ),
      );
    } else if (r.runtimeEol?.daysUntilEol !== undefined && r.runtimeEol.daysUntilEol <= 90) {
      console.log(
        pc.yellow(
          `⚠ ${runtimeLabel(r.runtimeTarget)} reaches end-of-life on ${r.runtimeEol.eol} (${r.runtimeEol.daysUntilEol} days) — plan the upgrade`,
        ),
      );
    }
  }
  // A data source was unreachable this run — the results are best-effort, so say so loudly
  // rather than letting a green gate imply "all clear" (e.g. KEV down = exploited-status unknown).
  if (r.degraded?.length) {
    console.log(
      pc.yellow(
        `⚠ degraded scan — could not reach ${r.degraded.join(', ')}; findings are best-effort (e.g. exploited-status may be unknown). Re-run to retry.`,
      ),
    );
  }
  // Coverage matters: without a lockfile the scan silently misses the transitive tree —
  // where most exploitable CVEs live — so say exactly what was scanned.
  if (r.ecosystem === 'npm' && r.lockfile === false) {
    console.log(
      pc.yellow(
        `⚠ no lockfile found — scanned ${direct.length} direct dependencies only (run npm install, then re-check to cover the transitive tree)`,
      ),
    );
  }
  // Name the script-runners, don't just count them — for npm's #1 supply-chain vector
  // the names are the signal, and a clean transitive would otherwise never be shown (#36).
  const scripted = r.findings.filter((f) => f.installScript);
  const suspicious = r.findings.filter((f) => f.suspiciousName).length;
  if (scripted.length > 0 || suspicious > 0) {
    const shown = scripted.slice(0, 6).map((f) => `${f.name}@${f.version ?? f.range}`);
    const more = scripted.length > shown.length ? ` +${scripted.length - shown.length} more` : '';
    const bits = [
      scripted.length > 0 ? `${scripted.length} run install scripts — ${shown.join(', ')}${more}` : '',
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
  printSources(r.sources);
}

function printPolicy(file: string, violations: Violation[], suppressed: Violation[]): void {
  // To stderr, so it never pollutes --json / --sbom stdout.
  if (violations.length === 0) {
    console.error(pc.green(`\n✓ policy ok (${file})`));
  } else {
    console.error(pc.red(`\n✗ ${violations.length} policy violation(s) (${file}):`));
    for (const v of violations) console.error(pc.red(`  · ${v.rule}: ${v.dep} — ${v.detail}`));
  }
  // Allow rules announce themselves: what the gate deliberately ignored, in plain sight.
  for (const s of suppressed) {
    console.error(pc.dim(`  · allowed: ${s.rule}: ${s.dep} — ${s.detail}`));
  }
}

const program = new Command();

program
  .name('preflight')
  .description('Pre-flight a dependency manifest: CVEs, framework-lockstep, auto-update safety.')
  // Version comes from package.json so a publish can't drift from --version. The relative path
  // works from both src/ (dev via tsx) and dist/ (published bundle) — same depth.
  .version((createRequire(import.meta.url)('../package.json') as { version: string }).version);

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
  .option(
    '--policy [file]',
    "gate the exit code on a policy file (default ./preflight.config.json; must exist when requested). Without this flag the config file is still consulted — but only for its 'runtimes' key, never the gate",
  )
  .option(
    '--fail-level <level>',
    "exit-1 threshold, same grammar as the Action: 'cve' (any advisory — default), 'kev' (confirmed-exploited), 'epss:<0-1>', 'severity:<low|medium|high|critical>' (unrated counts as low; KEV always fails)",
  )
  .option('--no-cache', 'bypass the on-disk 24h cache (~/.cache/preflight; set PREFLIGHT_CACHE_DIR to override)')
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
        failLevel?: string;
        cache?: boolean;
      },
    ) => {
      if (opts.cache === false) setCacheEnabled(false);
      // Core treats an unknown level as 'cve' (strict) — but at the CLI, reject typos loudly.
      if (
        opts.failLevel &&
        !/^(cve|kev|epss:\d*\.?\d+|severity:(low|medium|high|critical))$/i.test(opts.failLevel)
      ) {
        console.error(
          pc.red(
            `preflight: unknown --fail-level "${opts.failLevel}" — use cve, kev, epss:<0-1>, or severity:<low|medium|high|critical>`,
          ),
        );
        process.exitCode = 1;
        return;
      }
      // Load the policy first — its rules decide whether we need latest-version / health data.
      const policyFile =
        opts.policy === undefined
          ? undefined
          : typeof opts.policy === 'string'
            ? opts.policy
            : 'preflight.config.json';
      // mustExist: the user explicitly asked for a gate — a missing file must not silently pass.
      let policy: ReturnType<typeof loadPolicy> | undefined;
      try {
        policy = policyFile ? loadPolicy(policyFile, true) : undefined;
      } catch (err) {
        console.error(pc.red(`preflight: ${(err as Error).message}`));
        process.exitCode = 1;
        return;
      }
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
        // Same precedence as the Action: with a policy, the policy decides.
        if (opts.failLevel) {
          console.error(pc.dim('note: --policy governs the gate — --fail-level is ignored'));
        }
        const { violations, fail, suppressed } = evaluatePolicy(report.findings, policy, {
          runtimeEol: report.runtimeEol,
        });
        printPolicy(policyFile, violations, suppressed);
        if (fail) process.exitCode = 1;
      } else {
        // Default gate: non-zero exit when a vulnerability meets --fail-level ('cve' when
        // omitted: any CVE/malware — the pre-#34 behavior) — or when a dep cannot install
        // on an *explicitly* declared runtime (auto-detected targets only warn: a build
        // that was green yesterday shouldn't fail because a .nvmrc was noticed).
        const level = opts.failLevel ?? 'cve';
        const vulnFail = report.findings.some((f) => meetsVulnLevel(f, level));
        const explicitIncompat =
          (report.runtimeTarget?.explicit ?? false) && report.summary.incompatible > 0;
        if (vulnFail || explicitIncompat) {
          process.exitCode = 1;
        }
      }
    },
  );

registerPlanCommand(program);

await program.parseAsync();
