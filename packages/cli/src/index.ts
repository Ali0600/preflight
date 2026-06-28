#!/usr/bin/env node
import { analyze, setCacheEnabled, type Report, type Verdict } from '@preflight/core';
import { Command } from 'commander';
import pc from 'picocolors';

const BADGE: Record<Verdict, (s: string) => string> = {
  cve: (s) => pc.bgRed(pc.white(` ${s} `)),
  pinned: (s) => pc.bgYellow(pc.black(` ${s} `)),
  safe: (s) => pc.bgGreen(pc.black(` ${s} `)),
  stale: (s) => pc.bgMagenta(pc.white(` ${s} `)),
};

const LABEL: Record<Verdict, string> = { cve: 'CVE', pinned: 'PINNED', safe: 'SAFE', stale: 'STALE' };
const ORDER: Record<Verdict, number> = { cve: 0, pinned: 1, stale: 2, safe: 3 };

function printReport(r: Report): void {
  console.log();
  console.log(pc.bold(`Preflight — ${r.path}`));
  console.log(
    pc.dim(
      `${r.total} deps · ${r.summary.cve} CVE · ${r.summary.pinned} pinned · ${r.summary.stale} stale · ${r.summary.safe} safe`,
    ),
  );
  console.log();
  for (const f of [...r.findings].sort((a, b) => ORDER[a.verdict] - ORDER[b.verdict])) {
    const badge = BADGE[f.verdict](LABEL[f.verdict].padEnd(6));
    const latest =
      f.latest && f.latest !== f.version ? pc.dim(` · latest ${f.latest}`) : '';
    console.log(`${badge}  ${pc.bold(f.name)}${pc.dim(`@${f.version ?? f.range}`)}${latest}`);
    console.log(`          ${pc.dim(f.reason)}`);
    if (f.health !== undefined) {
      console.log(`          ${pc.dim(`OpenSSF health ${f.health.toFixed(1)}/10`)}`);
    }
  }
  console.log();
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
  .option('--latest', "fetch each dep's latest version + last-publish date (enables 'stale')")
  .option('--health', "fetch each dep's OpenSSF Scorecard from deps.dev")
  .option('--no-cache', 'bypass the on-disk 24h cache (.preflight-cache/)')
  .action(
    async (
      path: string,
      opts: { json?: boolean; latest?: boolean; health?: boolean; cache?: boolean },
    ) => {
      if (opts.cache === false) setCacheEnabled(false);
      let report: Report;
      try {
        report = await analyze(path, { latest: opts.latest, health: opts.health });
      } catch (err) {
        console.error(pc.red(`preflight: ${(err as Error).message}`));
        process.exitCode = 1;
        return;
      }
      if (opts.json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        printReport(report);
      }
      // Non-zero exit when any dependency carries a CVE, so CI can gate on it.
      if (report.summary.cve > 0) process.exitCode = 1;
    },
  );

await program.parseAsync();
