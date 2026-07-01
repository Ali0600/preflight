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

// Dirs that never hold a project's own manifest — skip them when looking one level down.
const SKIP_DIRS = new Set([
  'node_modules', 'dist', 'build', 'out', 'coverage', '.next', 'vendor',
  'examples', 'example', 'test', 'tests', '__tests__', 'fixtures', '.git',
]);

/** Immediate subdirectories worth probing for a manifest (many repos are monorepos: backend/, mobile/). */
function listSubdirs(repo: string): string[] {
  try {
    const names = JSON.parse(
      gh(['api', `repos/${repo}/contents`, '--jq', '[.[] | select(.type=="dir") | .name]']),
    ) as string[];
    return names.filter((d) => !d.startsWith('.') && !SKIP_DIRS.has(d));
  } catch {
    return [];
  }
}

/** Analyze any manifests in one directory of the repo (`prefix` '' = root, else 'backend/'). */
async function scanDir(repo: string, prefix: string): Promise<Scan[]> {
  const pkg = fetchFile(repo, `${prefix}package.json`);
  const req = fetchFile(repo, `${prefix}requirements.txt`);
  if (!pkg && !req) return [];

  const out: Scan[] = [];
  const tmp = mkdtempSync(join(tmpdir(), 'preflight-'));
  try {
    if (pkg) {
      writeFileSync(join(tmp, 'package.json'), pkg);
      const lock = fetchFile(repo, `${prefix}package-lock.json`); // gives the full transitive graph
      if (lock) writeFileSync(join(tmp, 'package-lock.json'), lock);
      out.push({ repo, manifest: `${prefix}package.json`, report: await analyze(join(tmp, 'package.json')) });
    }
    if (req) {
      writeFileSync(join(tmp, 'requirements.txt'), req);
      out.push({ repo, manifest: `${prefix}requirements.txt`, report: await analyze(join(tmp, 'requirements.txt')) });
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  return out;
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
    try {
      // Check the repo root plus one level down, so monorepo sub-projects (backend/, mobile/) count.
      const prefixes = ['', ...listSubdirs(repo).map((d) => `${d}/`)];
      let found = 0;
      for (const prefix of prefixes) {
        const dirScans = await scanDir(repo, prefix);
        scans.push(...dirScans);
        found += dirScans.length;
      }
      if (found > 0) process.stderr.write(`  scanned ${repo} (${found} manifest${found > 1 ? 's' : ''})\n`);
    } catch (err) {
      process.stderr.write(`  ! ${repo}: ${(err as Error).message}\n`);
    }
  }

  scans.sort((a, b) => riskScore(b.report) - riskScore(a.report));

  if (asJson) {
    console.log(JSON.stringify(scans, null, 2));
    return;
  }

  const risky = scans.filter((s) => riskScore(s.report) > 0);
  // A repo counts as clean only if *none* of its manifests are risky (a monorepo may have both).
  const riskyRepos = new Set(risky.map((s) => s.repo));

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
  const cleanRepos = [...new Set(scans.map((s) => s.repo))].filter((r) => !riskyRepos.has(r));
  if (cleanRepos.length) console.log(`\nClean (${cleanRepos.length}): ${cleanRepos.join(', ')}`);

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
