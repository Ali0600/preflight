'use client';

import type { Finding, Report } from '@preflight/core';
import { useState } from 'react';

import {
  SAMPLE_PACKAGE_JSON,
  VERDICT_META,
  healthGrade,
  insight,
  sortFindings,
  versionCell,
  worstCveSeverity,
} from './lib';

export default function Page() {
  const [filename, setFilename] = useState('package.json');
  const [content, setContent] = useState(SAMPLE_PACKAGE_JSON);
  const [health, setHealth] = useState(false);
  const [runtime, setRuntime] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  // A repo can carry several manifests (a package.json AND a Gemfile.lock), so the result is a
  // list; the paste flow simply returns a list of one.
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // One submit path for both flows so their loading/error handling can't drift apart.
  async function submit(endpoint: string, body: unknown) {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = (await res.json()) as { reports?: Report[]; error?: string } & Report;
      if (!res.ok) throw new Error(data.error ?? 'Analysis failed');
      setReports(Array.isArray(data.reports) ? data.reports : [data as Report]);
    } catch (e) {
      setError((e as Error).message);
      setReports([]);
    } finally {
      setLoading(false);
    }
  }

  const run = () => submit('/api/analyze', { filename, content, health, runtime });
  const runRepo = () => submit('/api/repo', { url: repoUrl, health });

  return (
    <>
      <div className="header">
        <i className="ti ti-shield-check" aria-hidden />
        <span className="header-title">Preflight</span>
        <span className="header-sub">· paste a manifest or a GitHub repo, pre-flight its dependencies</span>
      </div>

      <div className="form">
        <div className="controls">
          <input
            className="select"
            style={{ flex: 1, minWidth: 220 }}
            value={repoUrl}
            placeholder="Public GitHub repo — owner/repo, or a /tree/ or /blob/ URL"
            aria-label="GitHub repository URL"
            onChange={(e) => setRepoUrl(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && repoUrl.trim() && !loading) runRepo();
            }}
          />
          <button className="btn" onClick={runRepo} disabled={loading || !repoUrl.trim()}>
            {loading ? 'Pre-flighting…' : 'Scan repo'}
          </button>
        </div>
      </div>

      <div className="form">
        <textarea
          className="textarea"
          value={content}
          spellCheck={false}
          aria-label="manifest contents"
          onChange={(e) => setContent(e.target.value)}
        />
        <div className="controls">
          <select
            className="select"
            value={filename}
            aria-label="manifest type"
            onChange={(e) => setFilename(e.target.value)}
          >
            <option value="package.json">package.json (npm)</option>
            <option value="requirements.txt">requirements.txt (pip)</option>
            <option value="Gemfile.lock">Gemfile.lock (RubyGems)</option>
            <option value="go.mod">go.mod (Go)</option>
            <option value="Cargo.lock">Cargo.lock (crates.io)</option>
          </select>
          <label className="check">
            <input type="checkbox" checked={health} onChange={(e) => setHealth(e.target.checked)} />
            Include OpenSSF health (slower)
          </label>
          {/* Runtime installability is only checked for ecosystems with a registry client
              (npm/PyPI) — hide the box rather than take a target the scan would ignore. */}
          {!['Gemfile.lock', 'go.mod', 'Cargo.lock'].includes(filename) && (
            <input
              className="select"
              style={{ width: 150 }}
              value={runtime}
              placeholder={filename === 'requirements.txt' ? 'Python target, e.g. 3.9' : 'Node target, e.g. 18'}
              aria-label="target runtime version"
              onChange={(e) => setRuntime(e.target.value)}
            />
          )}

          <button className="btn" onClick={run} disabled={loading}>
            {loading ? 'Pre-flighting…' : 'Pre-flight'}
          </button>
        </div>
      </div>

      {error && <div className="error">{error}</div>}
      {reports.map((r) => (
        <Dashboard key={r.path} report={r} />
      ))}
    </>
  );
}

function Dashboard({ report }: { report: Report }) {
  const severity = worstCveSeverity(report);
  const grade = healthGrade(report);
  return (
    <>
      <div className="header-sub" style={{ marginBottom: 12 }}>
        {report.path} · {report.ecosystem}
        {report.runtimeTarget &&
          ` · target ${report.runtimeTarget.runtime === 'node' ? 'Node' : 'Python'} ${report.runtimeTarget.version}`}
      </div>

      <div className="cards">
        <Card label="Dependencies" value={String(report.total)} />
        {/* Malware shares the danger card — a malware-only scan must never read calm. */}
        <Card
          label="Known CVEs"
          value={String(report.summary.cve)}
          sub={report.summary.malware > 0 ? `+${report.summary.malware} MALWARE` : severity}
          tone={report.summary.cve > 0 || report.summary.malware > 0 ? 'danger' : undefined}
        />
        <Card
          label="Auto-update safe"
          value={String(report.summary.safe)}
          sub={`/ ${report.total}`}
          tone="success"
        />
        <Card label="Health grade" value={grade ?? '—'} sub={grade ? undefined : 'enable health'} />
      </div>

      <div className="panel">
        {sortFindings(report.findings).map((f) => (
          <Row key={f.name} finding={f} />
        ))}
      </div>

      <div className="callout">
        <i className="ti ti-bulb" aria-hidden />
        <div>{insight(report)}</div>
      </div>

      {report.sources && report.sources.length > 0 && (
        <div className="sources">
          <div className="sources-title">📡 Data sources — what this scan checked</div>
          {report.sources.map((s) => (
            <div key={s.name} className={`source-row ${s.status}`}>
              <span className={`source-status ${s.status}`} aria-hidden>
                {s.status === 'ok' ? '●' : s.status === 'degraded' ? '▲' : '○'}
              </span>
              <span className="source-name">{s.name}</span>
              <span className="source-detail">{s.detail}</span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function Card({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: 'danger' | 'success';
}) {
  return (
    <div className="card">
      <div className="card-label">{label}</div>
      <div className={`card-value ${tone ?? ''}`}>
        {value} {sub && <small>{sub}</small>}
      </div>
    </div>
  );
}

function Row({ finding }: { finding: Finding }) {
  const meta = VERDICT_META[finding.verdict];
  return (
    <div className="row">
      <div className="row-main">
        <div className="row-name">
          {finding.name} <span className="row-ver">{versionCell(finding)}</span>
          {finding.license && <span className="lic">{finding.license}</span>}
        </div>
        <div className="row-desc">{finding.reason}</div>
        {finding.suspiciousName && (
          <div className="row-warn">
            <i className="ti ti-alert-triangle" aria-hidden /> name resembles{' '}
            <code>{finding.suspiciousName.similarTo}</code> — confirm it&apos;s intended
          </div>
        )}
        {finding.installScript && (
          <div className="row-warn">
            <i className="ti ti-terminal-2" aria-hidden /> runs an install script
          </div>
        )}
        {finding.runtimeCompat?.latestIncompatible && finding.verdict !== 'incompatible' && (
          <div className="row-warn">
            <i className="ti ti-arrow-big-up-line" aria-hidden /> newest release drops the target
            runtime{finding.runtimeCompat.firstIncompatible &&
              ` — ignore ${finding.runtimeCompat.firstIncompatible}+ in your auto-updater`}
          </div>
        )}
        {finding.healthChecks && finding.healthChecks.length > 0 && (
          <div className="row-desc">weak: {finding.healthChecks.map((c) => c.name).join(', ')}</div>
        )}
      </div>
      <span className={`badge ${finding.verdict}`}>
        <i className={`ti ${meta.icon}`} aria-hidden /> {meta.label}
      </span>
    </div>
  );
}
