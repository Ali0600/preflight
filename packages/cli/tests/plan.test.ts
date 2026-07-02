import type { Plan } from '@preflight/core';
import { describe, expect, it } from 'vitest';

import { renderPlanRow, renderPlanText } from '../src/plan';

const PLAN: Plan = {
  ecosystem: 'PyPI',
  target: { runtime: 'python', version: '3.9', source: '--python flag', explicit: true },
  packages: [
    {
      name: 'uvicorn',
      dev: false,
      latest: '0.49.0',
      recommended: '0.39.0',
      floor: '>=0.39.0,<0.40',
      capped: true,
      constraint: '>=3.10',
      firstIncompatible: '0.40.0',
      lockstep: { pinned: false },
      vulns: [],
      note: '0.40.0+ requires Python >=3.10 — capped',
    },
    {
      name: 'httpx',
      dev: false,
      latest: '0.28.1',
      recommended: '0.28.1',
      floor: '>=0.28.1',
      capped: false,
      lockstep: { pinned: false },
      vulns: [],
      note: 'latest still supports Python 3.9 — no cap needed',
    },
  ],
  lockstepAdvice: undefined,
  artifacts: {
    manifest: { filename: 'requirements.txt', content: 'uvicorn>=0.39.0,<0.40\n' },
    dependabot: { filename: '.github/dependabot.yml', content: 'version: 2\n' },
  },
};

describe('renderPlanRow', () => {
  it('shows the recommended pin and why the latest was skipped', () => {
    const row = renderPlanRow(PLAN.packages[0]);
    expect(row).toContain('uvicorn@0.39.0');
    expect(row).toContain('(latest 0.49.0 incompatible)');
    expect(row).toContain('requires Python >=3.10');
  });
});

describe('renderPlanText', () => {
  it('renders the header, the capped count, and both artifacts', () => {
    const text = renderPlanText(PLAN);
    expect(text).toContain('Plan — 2 package(s) on Python 3.9');
    expect(text).toContain('1 capped below their latest');
    expect(text).toContain('── requirements.txt');
    expect(text).toContain('── .github/dependabot.yml');
    expect(text).toContain('uvicorn>=0.39.0,<0.40');
  });

  it('renders lockstep advice when a framework was seeded', () => {
    const text = renderPlanText({
      ...PLAN,
      lockstepAdvice: {
        framework: 'Expo',
        tool: 'npx expo install',
        members: ['expo', 'react'],
        prefixes: ['expo-'],
      },
    });
    expect(text).toContain('Expo lockstep: expo, react');
    expect(text).toContain('`npx expo install`');
  });
});
