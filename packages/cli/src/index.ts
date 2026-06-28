import { analyze, type Report, type Verdict } from '@preflight/core';
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
      `${r.total} deps · ${r.summary.cve} CVE · ${r.summary.pinned} pinned · ${r.summary.safe} safe`,
    ),
  );
  console.log();
  for (const f of [...r.findings].sort((a, b) => ORDER[a.verdict] - ORDER[b.verdict])) {
    const badge = BADGE[f.verdict](LABEL[f.verdict].padEnd(6));
    console.log(`${badge}  ${pc.bold(f.name)}${pc.dim(`@${f.version ?? f.range}`)}`);
    console.log(`          ${pc.dim(f.reason)}`);
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
  .option('--latest', "also fetch each dependency's latest published version")
  .action(async (path: string, opts: { json?: boolean; latest?: boolean }) => {
    let report: Report;
    try {
      report = await analyze(path, { latest: opts.latest });
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
  });

await program.parseAsync();
