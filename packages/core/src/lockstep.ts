import type { LockstepInfo } from './types';

export interface FrameworkSet {
  framework: string;
  /** The framework's own coordinated-upgrade command. */
  tool: string;
  /** Packages whose presence among a project's *direct* deps proves the framework is in use.
   * Membership below only attributes when a marker is present (see `presentFrameworks`) —
   * otherwise shared packages misattribute (`react` → "Expo" in a Next.js app). */
  markers: string[];
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
    markers: ['expo'],
    exact: ['expo', 'react', 'react-dom', 'react-native', 'react-native-web', 'jest-expo'],
    prefixes: ['expo-', '@expo/', '@react-native/', '@react-native-community/', '@react-native-async-storage/'],
  },
  {
    framework: 'Angular',
    tool: 'ng update',
    markers: ['@angular/core', '@angular/cli'],
    exact: ['@angular/cli'],
    prefixes: ['@angular/', '@angular-devkit/'],
  },
  {
    framework: 'Nx',
    tool: 'nx migrate',
    markers: ['nx'],
    exact: ['nx'],
    prefixes: ['@nx/', '@nrwl/'],
  },
  {
    // `react`/`react-dom` are members because `npx @next/codemod upgrade` bumps them together
    // with `next` (whose peer range coordinates the React major). Safe to include now that
    // attribution is marker-gated: a plain React/Vite app (no `next`) never matches this set.
    framework: 'Next.js',
    tool: 'npx @next/codemod upgrade',
    markers: ['next'],
    exact: ['next', 'eslint-config-next', 'react', 'react-dom'],
    prefixes: ['@next/'],
  },
  {
    framework: 'Nuxt',
    tool: 'npx nuxi upgrade',
    markers: ['nuxt'],
    exact: ['nuxt'],
    prefixes: ['@nuxt/', '@nuxtjs/'],
  },
  {
    // `@sveltejs/kit` + adapters/plugins move together; bare `svelte` is omitted because
    // plenty of projects use Svelte without SvelteKit and it versions independently.
    framework: 'SvelteKit',
    tool: 'npx sv migrate',
    markers: ['@sveltejs/kit'],
    exact: [],
    prefixes: ['@sveltejs/'],
  },
  {
    framework: 'Remix',
    tool: 'bump all @remix-run/* to the same version',
    markers: ['@remix-run/react', '@remix-run/node', '@remix-run/serve', '@remix-run/dev'],
    exact: [],
    prefixes: ['@remix-run/'],
  },
  {
    framework: 'Astro',
    tool: 'npx @astrojs/upgrade',
    markers: ['astro'],
    exact: ['astro'],
    prefixes: ['@astrojs/'],
  },
];

/** The registry subset whose marker package appears among `names` (a project's direct deps). */
export function presentFrameworks(names: Iterable<string>): FrameworkSet[] {
  const have = new Set(names);
  return FRAMEWORK_SETS.filter((s) => s.markers.some((m) => have.has(m)));
}

/**
 * Classify a package name against the framework-lockstep registry.
 * Pass `context` (from `presentFrameworks`, or a declared `--framework`) so only frameworks
 * actually in the project can claim a package — shared members like `react` belong to several
 * sets, and attributing to an absent framework is wrong advice. Without `context` every
 * registered set is considered (a registry-wide "is this in any set?" query).
 */
export function lockstepFor(name: string, context?: FrameworkSet[]): LockstepInfo {
  for (const set of context ?? FRAMEWORK_SETS) {
    if (set.exact.includes(name) || set.prefixes.some((p) => name.startsWith(p))) {
      return { pinned: true, framework: set.framework, tool: set.tool };
    }
  }
  return { pinned: false };
}
