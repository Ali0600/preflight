import type { LockstepInfo } from './types';

interface FrameworkSet {
  framework: string;
  /** The framework's own coordinated-upgrade command. */
  tool: string;
  exact: string[];
  prefixes: string[];
  /** Packages whose presence in a manifest means this framework is in play.
   * Membership (`exact`/`prefixes`) is NOT presence: `react` belongs to Expo's
   * set, but only `expo` itself proves a project is an Expo project. */
  anchors: string[];
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
    anchors: ['expo'],
  },
  {
    framework: 'Angular',
    tool: 'ng update',
    exact: ['@angular/cli'],
    prefixes: ['@angular/', '@angular-devkit/'],
    anchors: ['@angular/core', '@angular/cli'],
  },
  {
    framework: 'Nx',
    tool: 'nx migrate',
    exact: ['nx'],
    prefixes: ['@nx/', '@nrwl/'],
    anchors: ['nx'],
  },
  {
    // Next coordinates its own packages; `react`/`react-dom` are intentionally left out
    // (Next supports independent React bumps within its range, and Expo already claims them).
    framework: 'Next.js',
    tool: 'npx @next/codemod upgrade',
    exact: ['next', 'eslint-config-next'],
    prefixes: ['@next/'],
    anchors: ['next'],
  },
  {
    framework: 'Nuxt',
    tool: 'npx nuxi upgrade',
    exact: ['nuxt'],
    prefixes: ['@nuxt/', '@nuxtjs/'],
    anchors: ['nuxt'],
  },
  {
    // `@sveltejs/kit` + adapters/plugins move together; bare `svelte` is omitted because
    // plenty of projects use Svelte without SvelteKit and it versions independently.
    framework: 'SvelteKit',
    tool: 'npx sv migrate',
    exact: [],
    prefixes: ['@sveltejs/'],
    anchors: ['@sveltejs/kit'],
  },
  {
    framework: 'Remix',
    tool: 'bump all @remix-run/* to the same version',
    exact: [],
    prefixes: ['@remix-run/'],
    anchors: ['@remix-run/react', '@remix-run/node'],
  },
  {
    framework: 'Astro',
    tool: 'npx @astrojs/upgrade',
    exact: ['astro'],
    prefixes: ['@astrojs/'],
    anchors: ['astro'],
  },
];

/** Frameworks whose anchor package appears among `depNames` — i.e. actually in play.
 * Drives context-aware attribution: `react` should only read "Expo-coordinated" in a
 * project that actually depends on `expo` (issue #18: a `--framework next.js` plan
 * labeled react "update via npx expo install"). */
export function presentFrameworks(depNames: Iterable<string>): Set<string> {
  const names = depNames instanceof Set ? depNames : new Set(depNames);
  const present = new Set<string>();
  for (const set of FRAMEWORK_SETS) {
    if (set.anchors.some((a) => names.has(a))) present.add(set.framework);
  }
  return present;
}

/** Classify a package name against the framework-lockstep registry.
 *
 * With `present` (from `presentFrameworks`), only those frameworks can claim the
 * package — an empty set means "no framework in play", so nothing is pinned.
 * Without it (registry-wide lookup), the first matching set wins, as before. */
export function lockstepFor(name: string, present?: ReadonlySet<string>): LockstepInfo {
  for (const set of FRAMEWORK_SETS) {
    if (present !== undefined && !present.has(set.framework)) continue;
    if (set.exact.includes(name) || set.prefixes.some((p) => name.startsWith(p))) {
      return { pinned: true, framework: set.framework, tool: set.tool };
    }
  }
  return { pinned: false };
}
