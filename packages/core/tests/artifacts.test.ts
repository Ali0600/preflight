import { describe, expect, it } from 'vitest';

import { renderDependabot, renderManifest, trimBoundary } from '../src/artifacts';
import type { Plan, PackagePlan } from '../src/plan';
import type { RuntimeTarget } from '../src/types';

const PY39: RuntimeTarget = { runtime: 'python', version: '3.9', source: '--python flag', explicit: true };

function pkg(over: Partial<PackagePlan> & { name: string }): PackagePlan {
  return {
    dev: false,
    latest: '1.0.0',
    recommended: '1.0.0',
    floor: '>=1.0.0',
    capped: false,
    lockstep: { pinned: false },
    vulns: [],
    note: 'latest still supports Python 3.9 — no cap needed',
    ...over,
  };
}

function plan(over: Partial<Plan>): Plan {
  return {
    ecosystem: 'PyPI',
    target: PY39,
    packages: [],
    artifacts: { manifest: { filename: '', content: '' }, dependabot: { filename: '', content: '' } },
    ...over,
  };
}

describe('trimBoundary', () => {
  it('drops redundant trailing zero segments only', () => {
    expect(trimBoundary('0.40.0')).toBe('0.40');
    expect(trimBoundary('9.0.0')).toBe('9');
    expect(trimBoundary('3.10')).toBe('3.10');
    expect(trimBoundary('1.2.3')).toBe('1.2.3');
    expect(trimBoundary('2.0.1')).toBe('2.0.1');
  });
});

describe('renderManifest (pip)', () => {
  it('writes floors with notes, dev tags, and comments-out packages with no floor', () => {
    const p = plan({
      packages: [
        pkg({ name: 'uvicorn', floor: '>=0.39.0,<0.40', capped: true, note: '0.40.0+ requires Python >=3.10 — capped' }),
        pkg({ name: 'pytest', dev: true, floor: '>=8.4.1,<9', note: '9.0.0+ requires Python >=3.10 — capped' }),
        pkg({ name: 'ghost', recommended: undefined, floor: undefined, note: 'no registry metadata found — check the package name' }),
      ],
    });
    const { filename, content } = renderManifest(p);
    expect(filename).toBe('requirements.txt');
    expect(content).toContain('target: Python 3.9');
    expect(content).toMatch(/uvicorn>=0\.39\.0,<0\.40\s+# 0\.40\.0\+ requires Python >=3\.10/);
    expect(content).toMatch(/pytest>=8\.4\.1,<9\s+# dev · 9\.0\.0\+/);
    expect(content).toContain('# ghost: no registry metadata');
  });
});

describe('renderManifest (npm)', () => {
  it('emits valid package.json with engines and dev split', () => {
    const p = plan({
      ecosystem: 'npm',
      target: { runtime: 'node', version: '18', source: '--node flag', explicit: true },
      packages: [
        pkg({ name: 'axios', floor: '^1.7.0' }),
        pkg({ name: 'vitest', dev: true, floor: '^3.0.0' }),
      ],
    });
    const { filename, content } = renderManifest(p);
    expect(filename).toBe('package.json');
    const json = JSON.parse(content) as Record<string, Record<string, string>>;
    expect(json.engines.node).toBe('>=18');
    expect(json.dependencies.axios).toBe('^1.7.0');
    expect(json.devDependencies.vitest).toBe('^3.0.0');
  });
});

describe('renderDependabot', () => {
  it('pip: grouped weekly updates + one ignore per capped package (lockstep members excluded)', () => {
    const p = plan({
      packages: [
        pkg({ name: 'uvicorn', capped: true, firstIncompatible: '0.40.0' }),
        pkg({ name: 'httpx' }), // uncapped — no ignore
      ],
    });
    const yml = renderDependabot(p).content;
    expect(yml).toContain('package-ecosystem: pip');
    expect(yml).toContain('interval: weekly');
    expect(yml).toContain('update-types: [minor, patch]');
    expect(yml).toContain('- dependency-name: uvicorn');
    expect(yml).toContain("versions: ['>=0.40']");
    expect(yml).not.toContain('httpx');
  });

  it('always adds a github-actions ecosystem block (repos using this file have workflows) (#22)', () => {
    const yml = renderDependabot(plan({ packages: [pkg({ name: 'httpx' })] })).content;
    expect(yml).toContain('- package-ecosystem: github-actions');
    expect(yml.indexOf('github-actions')).toBeGreaterThan(yml.indexOf('package-ecosystem: pip'));
  });

  it('npm: lockstep advice becomes exact + quoted wildcard ignores', () => {
    const p = plan({
      ecosystem: 'npm',
      target: { runtime: 'node', version: '18', source: '--node flag', explicit: true },
      packages: [],
      lockstepAdvice: {
        framework: 'Expo',
        tool: 'npx expo install',
        members: ['expo', 'react'],
        prefixes: ['expo-', '@expo/'],
      },
    });
    const yml = renderDependabot(p).content;
    expect(yml).toContain('package-ecosystem: npm');
    expect(yml).toContain('- dependency-name: expo\n');
    expect(yml).toContain("- dependency-name: 'expo-*'");
    expect(yml).toContain("- dependency-name: '@expo/*'");
    expect(yml).toContain('npx expo install');
  });

  it('no capped packages and no lockstep -> no ignore block at all', () => {
    const yml = renderDependabot(plan({ packages: [pkg({ name: 'httpx' })] })).content;
    expect(yml).not.toContain('ignore:');
  });
});
