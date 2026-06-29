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
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ filename, content, health }),
      });
      const data = (await res.json()) as Report & { error?: string };
      if (!res.ok) throw new Error(data.error ?? 'Analysis failed');
      setReport(data);
    } catch (e) {
      setError((e as Error).message);
      setReport(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="header">
        <i className="ti ti-shield-check" aria-hidden />
        <span className="header-title">Preflight</span>
        <span className="header-sub">· paste a manifest, pre-flight its dependencies</span>
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
          </select>
          <label className="check">
            <input type="checkbox" checked={health} onChange={(e) => setHealth(e.target.checked)} />
            Include OpenSSF health (slower)
          </label>
          <button className="btn" onClick={run} disabled={loading}>
            {loading ? 'Pre-flighting…' : 'Pre-flight'}
          </button>
        </div>
      </div>

      {error && <div className="error">{error}</div>}
      {report && <Dashboard report={report} />}
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
      </div>

      <div className="cards">
        <Card label="Dependencies" value={String(report.total)} />
        <Card
          label="Known CVEs"
          value={String(report.summary.cve)}
          sub={severity}
          tone={report.summary.cve > 0 ? 'danger' : undefined}
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
        </div>
        <div className="row-desc">{finding.reason}</div>
      </div>
      <span className={`badge ${finding.verdict}`}>
        <i className={`ti ${meta.icon}`} aria-hidden /> {meta.label}
      </span>
    </div>
  );
}
