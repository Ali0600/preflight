import type { Plan } from '@preflight/core';
import { describe, expect, it } from 'vitest';

import { renderPlanRow, renderPlanText, splitPackages } from '../src/plan';

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

describe('splitPackages (#19: --dev must take every following package)', () => {
  it('flattens variadic values and tolerates commas and blanks', () => {
    expect(splitPackages(['typescript', '@types/node', 'eslint'])).toEqual([
      'typescript',
      '@types/node',
      'eslint',
    ]);
    expect(splitPackages(['a,b', 'c', ' ', ''])).toEqual(['a', 'b', 'c']);
    expect(splitPackages(undefined)).toEqual([]);
  });
});

describe('renderPlanRow', () => {
  it('shows the recommended pin and why the latest was skipped', () => {
    const row = renderPlanRow(PLAN.packages[0]);
    expect(row).toContain('uvicorn@0.39.0');
    expect(row).toContain('(latest 0.49.0 incompatible)');
    expect(row).toContain('requires Python >=3.10');
  });

  it('marks a package held back by a known-bad pair (#31)', () => {
    const row = renderPlanRow({
      ...PLAN.packages[1],
      name: 'eslint',
      latest: '10.6.0',
      recommended: '9.39.4',
      heldBack: { with: 'eslint-config-next@16.2.10', firstBad: '10.0.0', reason: 'r' },
      note: 'held back: 10.0.0+ breaks with eslint-config-next@16.2.10 — r',
    });
    expect(row).toContain('eslint@9.39.4');
    expect(row).toContain('(latest 10.6.0 held back)');
    expect(row).toContain('breaks with eslint-config-next@16.2.10');
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
