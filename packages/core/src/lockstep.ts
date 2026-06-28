import type { LockstepInfo } from './types';

interface FrameworkSet {
  framework: string;
  /** The framework's own coordinated-upgrade command. */
  tool: string;
  exact: string[];
  prefixes: string[];
}

// Data-driven registry of framework-managed ("lockstep") package sets. A generic
// per-package auto-updater (Dependabot/Renovate) breaks these because the framework
// pins them as a coherent group — so we flag them as "update via the framework tool".
// THIS LIST IS THE PRODUCT'S EDGE: keep extending it as frameworks evolve.
export const FRAMEWORK_SETS: FrameworkSet[] = [
  {
    framework: 'Expo',
    tool: 'npx expo install',
    exact: ['expo', 'react', 'react-dom', 'react-native', 'react-native-web', 'jest-expo'],
    prefixes: ['expo-', '@expo/', '@react-native/', '@react-native-community/', '@react-native-async-storage/'],
  },
  {
    framework: 'Angular',
    tool: 'ng update',
    exact: ['@angular/cli'],
    prefixes: ['@angular/', '@angular-devkit/'],
  },
  {
    framework: 'Nx',
    tool: 'nx migrate',
    exact: ['nx'],
    prefixes: ['@nx/', '@nrwl/'],
  },
  {
    // Next coordinates its own packages; `react`/`react-dom` are intentionally left out
    // (Next supports independent React bumps within its range, and Expo already claims them).
    framework: 'Next.js',
    tool: 'npx @next/codemod upgrade',
    exact: ['next', 'eslint-config-next'],
    prefixes: ['@next/'],
  },
  {
    framework: 'Nuxt',
    tool: 'npx nuxi upgrade',
    exact: ['nuxt'],
    prefixes: ['@nuxt/', '@nuxtjs/'],
  },
  {
    // `@sveltejs/kit` + adapters/plugins move together; bare `svelte` is omitted because
    // plenty of projects use Svelte without SvelteKit and it versions independently.
    framework: 'SvelteKit',
    tool: 'npx sv migrate',
    exact: [],
    prefixes: ['@sveltejs/'],
  },
  {
    framework: 'Remix',
    tool: 'bump all @remix-run/* to the same version',
    exact: [],
    prefixes: ['@remix-run/'],
  },
  {
    framework: 'Astro',
    tool: 'npx @astrojs/upgrade',
    exact: ['astro'],
    prefixes: ['@astrojs/'],
  },
];

/** Classify a package name against the framework-lockstep registry. */
export function lockstepFor(name: string): LockstepInfo {
  for (const set of FRAMEWORK_SETS) {
    if (set.exact.includes(name) || set.prefixes.some((p) => name.startsWith(p))) {
      return { pinned: true, framework: set.framework, tool: set.tool };
    }
  }
  return { pinned: false };
}
