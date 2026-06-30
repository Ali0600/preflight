/**
 * Read-only fleet scan: run Preflight across every repo you own that has a manifest.
 *
 * Uses your existing `gh` login *only* to list repos and download manifests — it writes
 * nothing to any repo. The analysis itself stays keyless (OSV / deps.dev / npm / PyPI).
 *
 *   npm run scan:repos              # all your non-archived, non-fork repos
 *   npm run scan:repos -- --json    # machine-readable output
 *
 * Run via tsx so it can import the TypeScript engine directly.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { analyze, type Report } from '@preflight/core';

function gh(args: string[]): string {
  // stderr ignored: a missing file is a normal 404 we handle by returning undefined.
  return execFileSync('gh', args, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
}

/** Fetch a file's text from a repo's default branch, or undefined if it's absent. */
function fetchFile(repo: string, path: string): string | undefined {
  try {
    return Buffer.from(gh(['api', `repos/${repo}/contents/${path}`, '--jq', '.content']), 'base64').toString('utf8');
  } catch {
    return undefined; // 404 — the repo doesn't have this file
  }
}

interface Scan {
  repo: string;
  manifest: string;
  report: Report;
}

/** Risk ordering: malware first, then CVEs, then supply-chain flags. */
function riskScore(r: Report): number {
  const scripts = r.findings.filter((f) => f.installScript).length;
  const suspicious = r.findings.filter((f) => f.suspiciousName).length;
  return r.summary.malware * 1e6 + r.summary.cve * 1e3 + suspicious * 100 + scripts;
}

function line(s: Scan): string {
  const r = s.report;
  const bits = [
    r.summary.malware ? `🦠 ${r.summary.malware} malware` : '',
    r.summary.cve ? `🟥 ${r.summary.cve} CVE` : '',
    r.findings.some((f) => f.suspiciousName) ? `⚠ ${r.findings.filter((f) => f.suspiciousName).length} typosquat` : '',
    r.summary.pinned ? `🔒 ${r.summary.pinned} pinned` : '',
    r.findings.filter((f) => f.installScript).length ? `⚙ ${r.findings.filter((f) => f.installScript).length} scripts` : '',
  ].filter(Boolean);
  return `${s.repo} (${s.manifest}) · ${r.total} deps — ${bits.length ? bits.join(' · ') : 'clean ✅'}`;
}

/** The scary specifics worth naming: malware + typosquat package names. */
function highlights(s: Scan): string[] {
  return s.report.findings
    .filter((f) => f.verdict === 'malware' || f.suspiciousName)
    .map((f) =>
      f.verdict === 'malware'
        ? `      🦠 ${f.name}@${f.version ?? f.range} — malicious`
        : `      ⚠ ${f.name} — resembles ${f.suspiciousName!.similarTo}`,
    );
}

async function main(): Promise<void> {
  const asJson = process.argv.includes('--json');
  process.stderr.write('Listing repos…\n');
  const repos = (
    JSON.parse(gh(['repo', 'list', '--source', '--no-archived', '--limit', '1000', '--json', 'nameWithOwner'])) as {
      nameWithOwner: string;
    }[]
  ).map((r) => r.nameWithOwner);

  const scans: Scan[] = [];
  for (const repo of repos) {
    const pkg = fetchFile(repo, 'package.json');
    const req = fetchFile(repo, 'requirements.txt');
    if (!pkg && !req) continue; // scope: only repos with a manifest

    const dir = mkdtempSync(join(tmpdir(), 'preflight-'));
    try {
      if (pkg) {
        writeFileSync(join(dir, 'package.json'), pkg);
        const lock = fetchFile(repo, 'package-lock.json'); // gives the full transitive graph
        if (lock) writeFileSync(join(dir, 'package-lock.json'), lock);
        scans.push({ repo, manifest: 'package.json', report: await analyze(join(dir, 'package.json')) });
      }
      if (req) {
        writeFileSync(join(dir, 'requirements.txt'), req);
        scans.push({ repo, manifest: 'requirements.txt', report: await analyze(join(dir, 'requirements.txt')) });
      }
      process.stderr.write(`  scanned ${repo}\n`);
    } catch (err) {
      process.stderr.write(`  ! ${repo}: ${(err as Error).message}\n`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  scans.sort((a, b) => riskScore(b.report) - riskScore(a.report));

  if (asJson) {
    console.log(JSON.stringify(scans, null, 2));
    return;
  }

  const risky = scans.filter((s) => riskScore(s.report) > 0);
  const clean = scans.filter((s) => riskScore(s.report) === 0);

  console.log(`\nPreflight fleet scan — ${scans.length} manifest(s) across ${new Set(scans.map((s) => s.repo)).size} repo(s)\n`);
  if (risky.length === 0) {
    console.log('No malware, CVEs, or typosquats found. ✅');
  } else {
    console.log(`Needs attention (${risky.length}):`);
    for (const s of risky) {
      console.log(`  ${line(s)}`);
      for (const h of highlights(s)) console.log(h);
    }
  }
  if (clean.length) console.log(`\nClean (${clean.length}): ${clean.map((s) => s.repo).join(', ')}`);

  const totals = scans.reduce(
    (a, s) => ({ malware: a.malware + s.report.summary.malware, cve: a.cve + s.report.summary.cve }),
    { malware: 0, cve: 0 },
  );
  console.log(`\nTotals: ${totals.malware} malware · ${totals.cve} CVE findings across the fleet.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
