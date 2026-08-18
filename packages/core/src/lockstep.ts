import type { Ecosystem, LockstepInfo } from './types';

interface FrameworkSet {
  framework: string;
  /** The framework's own coordinated-upgrade command. */
  tool: string;
  /** Which ecosystem's package names these are. Defaults to npm. Without this a gem named
   * `rails` and an npm package named `rails` would claim each other's projects. */
  ecosystem?: Ecosystem;
  exact: string[];
  prefixes: string[];
  /** Packages whose presence in a manifest means this framework is in play.
   * Membership (`exact`/`prefixes`) is NOT presence: `react` belongs to Expo's
   * set, but only `expo` itself proves a project is an Expo project. */
  anchors: string[];
}

/** A set with no explicit ecosystem is npm's (the registry started npm-only). */
function ecosystemOf(set: FrameworkSet): Ecosystem {
  return set.ecosystem ?? 'npm';
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
  {
    // Prisma's CLI warns at runtime — "Versions of prisma@X and @prisma/client@Y don't match.
    // This might lead to unexpected behavior" — but `@prisma/client`'s peer range on `prisma` is
    // literally `*`, so npm and Dependabot see no conflict at all. That gap is the whole point of
    // this registry. Deliberately NO `@prisma/` prefix: verified 2026-08-18 that `@prisma/dev`
    // (0.25.1) and `@prisma/studio-core` (0.33.0) sit off the 7.9.1 line, so a prefix would hand
    // out false advice about packages Prisma does not coordinate.
    framework: 'Prisma',
    tool: 'bump prisma and @prisma/client to the same version together',
    exact: ['prisma', '@prisma/client'],
    prefixes: [],
    anchors: ['prisma', '@prisma/client'],
  },
  {
    // Every Storybook package rides the monorepo version: `@storybook/react@10.5.9` peers
    // `storybook: ^10.5.9` and pins `@storybook/react-dom-shim@10.5.9` exactly (verified, as is
    // `@storybook/addon-docs@10.5.9`). Bumping the core without the addons is the classic break.
    framework: 'Storybook',
    tool: 'npx storybook@latest upgrade',
    exact: ['storybook'],
    prefixes: ['@storybook/'],
    anchors: ['storybook'],
  },
  {
    // The strongest evidence of any entry here: `@trpc/client` declares
    // `peerDependencies: { "@trpc/server": "11.18.0" }` — an EXACT pin, not a range.
    framework: 'tRPC',
    tool: 'bump all @trpc/* to the same version',
    exact: [],
    prefixes: ['@trpc/'],
    anchors: ['@trpc/server', '@trpc/client'],
  },
  {
    // Sentry's own migration guide: "make sure to upgrade all of them to the same version", and
    // `@sentry/node@10.70.0` pins `@sentry/core`/`@sentry/node-core`/`@sentry/server-utils` at
    // 10.70.0 exactly. But NO `@sentry/` prefix — verified 2026-08-18 that the build-tool and
    // internal packages version independently (`@sentry/cli` 3.6.2, `@sentry/webpack-plugin` and
    // `@sentry/vite-plugin` 5.4.0, `@sentry/conventions` 0.19.0), so a prefix would wrongly tell
    // people to hold those back. The SDK runtimes are listed explicitly instead.
    framework: 'Sentry',
    tool: 'bump all Sentry SDK packages to the same version',
    exact: [
      '@sentry/core', '@sentry/browser', '@sentry/node', '@sentry/react', '@sentry/vue',
      '@sentry/angular', '@sentry/svelte', '@sentry/sveltekit', '@sentry/nextjs', '@sentry/nuxt',
      '@sentry/remix', '@sentry/astro', '@sentry/solid', '@sentry/solidstart', '@sentry/bun',
      '@sentry/deno', '@sentry/nestjs', '@sentry/aws-serverless', '@sentry/cloudflare',
      '@sentry/vercel-edge', '@sentry/opentelemetry', '@sentry/profiling-node',
      '@sentry/react-router', '@sentry/google-cloud-serverless',
    ],
    prefixes: [],
    anchors: [
      '@sentry/browser', '@sentry/node', '@sentry/react', '@sentry/vue', '@sentry/angular',
      '@sentry/svelte', '@sentry/sveltekit', '@sentry/nextjs', '@sentry/nuxt', '@sentry/remix',
      '@sentry/astro', '@sentry/solid', '@sentry/bun', '@sentry/deno', '@sentry/nestjs',
      '@sentry/aws-serverless', '@sentry/cloudflare', '@sentry/react-router',
    ],
  },
  {
    // The textbook lockstep set: the `rails` gem declares every component at `= X.Y.Z` exactly
    // (verified against the rubygems API for both 7.1.3 and 8.1.3.1 — all 12 components `=`,
    // while `bundler` is `>= 1.15.0` and is therefore NOT a member). Bumping one component on
    // its own is unresolvable while `rails` is present; Bundler moves the whole set together.
    // No prefixes: `action*`/`active*` are ordinary namespaces on rubygems.org (actionpack-*
    // plugins, activerecord-import, …) that Rails does not coordinate — matching them would
    // hand out false "framework-pinned" advice.
    framework: 'Rails',
    tool: 'bundle update rails',
    ecosystem: 'RubyGems',
    exact: [
      'rails', 'railties', 'actioncable', 'actionmailbox', 'actionmailer', 'actionpack',
      'actiontext', 'actionview', 'activejob', 'activemodel', 'activerecord', 'activestorage',
      'activesupport',
    ],
    prefixes: [],
    anchors: ['rails', 'railties'],
  },
];

/** Frameworks whose anchor package appears among `depNames` — i.e. actually in play.
 * Drives context-aware attribution: `react` should only read "Expo-coordinated" in a
 * project that actually depends on `expo` (issue #18: a `--framework next.js` plan
 * labeled react "update via npx expo install").
 *
 * `ecosystem` scopes the search to sets whose names live in the same registry — package
 * names are only unique *within* an ecosystem, so a gem must never anchor an npm framework. */
export function presentFrameworks(depNames: Iterable<string>, ecosystem: Ecosystem = 'npm'): Set<string> {
  const names = depNames instanceof Set ? depNames : new Set(depNames);
  const present = new Set<string>();
  for (const set of FRAMEWORK_SETS) {
    if (ecosystemOf(set) !== ecosystem) continue;
    if (set.anchors.some((a) => names.has(a))) present.add(set.framework);
  }
  return present;
}

/** Classify a package name against the framework-lockstep registry.
 *
 * With `present` (from `presentFrameworks`), only those frameworks can claim the
 * package — an empty set means "no framework in play", so nothing is pinned.
 * Without it (registry-wide lookup), the first matching set wins, as before.
 * `ecosystem` scopes the search the same way `presentFrameworks` does. */
export function lockstepFor(
  name: string,
  present?: ReadonlySet<string>,
  ecosystem: Ecosystem = 'npm',
): LockstepInfo {
  for (const set of FRAMEWORK_SETS) {
    if (ecosystemOf(set) !== ecosystem) continue;
    if (present !== undefined && !present.has(set.framework)) continue;
    if (set.exact.includes(name) || set.prefixes.some((p) => name.startsWith(p))) {
      return { pinned: true, framework: set.framework, tool: set.tool };
    }
  }
  return { pinned: false };
}
