import { describe, expect, it } from 'vitest';

import { lockstepFor, presentFrameworks } from '../src/lockstep';

describe('lockstepFor', () => {
  it('flags Expo-managed packages with the framework + tool', () => {
    expect(lockstepFor('react-native')).toMatchObject({
      pinned: true,
      framework: 'Expo',
      tool: 'npx expo install',
    });
    expect(lockstepFor('expo-status-bar').pinned).toBe(true); // expo- prefix
    expect(lockstepFor('@expo/metro-runtime').pinned).toBe(true); // @expo/ prefix
    expect(lockstepFor('jest-expo').pinned).toBe(true);
  });

  it('flags Angular and Nx sets', () => {
    expect(lockstepFor('@angular/core')).toMatchObject({ framework: 'Angular', tool: 'ng update' });
    expect(lockstepFor('@nx/workspace')).toMatchObject({ framework: 'Nx' });
  });

  it('flags the JS framework sets with the right tool', () => {
    expect(lockstepFor('next')).toMatchObject({ framework: 'Next.js' });
    expect(lockstepFor('eslint-config-next').pinned).toBe(true);
    expect(lockstepFor('@next/font').pinned).toBe(true);
    expect(lockstepFor('nuxt')).toMatchObject({ framework: 'Nuxt', tool: 'npx nuxi upgrade' });
    expect(lockstepFor('@nuxt/kit').pinned).toBe(true);
    expect(lockstepFor('@sveltejs/kit')).toMatchObject({ framework: 'SvelteKit' });
    expect(lockstepFor('@remix-run/node')).toMatchObject({ framework: 'Remix' });
    expect(lockstepFor('astro')).toMatchObject({ framework: 'Astro', tool: 'npx @astrojs/upgrade' });
    expect(lockstepFor('@astrojs/react').pinned).toBe(true);
  });

  it('leaves independent packages unpinned', () => {
    expect(lockstepFor('fastapi').pinned).toBe(false);
    expect(lockstepFor('lodash').pinned).toBe(false);
    expect(lockstepFor('react-query').pinned).toBe(false); // starts with "react" but not a set member
    expect(lockstepFor('svelte').pinned).toBe(false); // bare svelte ≠ SvelteKit-pinned
    expect(lockstepFor('next-auth').pinned).toBe(false); // starts with "next" but not a member
  });
});

describe('presentFrameworks (anchor detection)', () => {
  it('detects frameworks by their anchor packages, not by shared members', () => {
    // react is an Expo set *member*, but only `expo` itself proves Expo is in play
    expect(presentFrameworks(['next', 'react', 'react-dom', 'zod'])).toEqual(new Set(['Next.js']));
    expect(presentFrameworks(['expo', 'react', 'react-native'])).toEqual(new Set(['Expo']));
    expect(presentFrameworks(['@angular/core', 'rxjs'])).toEqual(new Set(['Angular']));
    expect(presentFrameworks(['@remix-run/react'])).toEqual(new Set(['Remix']));
    expect(presentFrameworks(['lodash', 'react'])).toEqual(new Set());
  });
});

describe('lockstepFor with a present-frameworks context (#18)', () => {
  it('react is Expo-coordinated only when Expo is actually present', () => {
    expect(lockstepFor('react', new Set(['Next.js'])).pinned).toBe(false);
    expect(lockstepFor('react', new Set(['Expo']))).toMatchObject({ pinned: true, framework: 'Expo' });
    expect(lockstepFor('react', new Set()).pinned).toBe(false); // no framework in play
  });

  it('the present framework still claims its own members', () => {
    expect(lockstepFor('next', new Set(['Next.js']))).toMatchObject({ framework: 'Next.js' });
    expect(lockstepFor('eslint-config-next', new Set(['Next.js'])).pinned).toBe(true);
  });

  it('undefined context keeps the registry-wide legacy behavior', () => {
    expect(lockstepFor('react')).toMatchObject({ pinned: true, framework: 'Expo' });
  });
});

describe('Rails (RubyGems) — ecosystem scoping', () => {
  const rails = new Set(['Rails']);

  it('claims the components the rails gem pins at "= X.Y.Z"', () => {
    // Verified against the rubygems API for rails 7.1.3 and 8.1.3.1: all 12 components are
    // declared `= <same version>`, so bumping one alone is unresolvable.
    expect(lockstepFor('activerecord', rails, 'RubyGems')).toMatchObject({
      pinned: true,
      framework: 'Rails',
      tool: 'bundle update rails',
    });
    for (const gem of ['railties', 'actionpack', 'actionview', 'activesupport', 'activestorage']) {
      expect(lockstepFor(gem, rails, 'RubyGems').pinned).toBe(true);
    }
  });

  it('leaves independent gems — and lookalike namespaces — unpinned', () => {
    expect(lockstepFor('nokogiri', rails, 'RubyGems').pinned).toBe(false);
    expect(lockstepFor('puma', rails, 'RubyGems').pinned).toBe(false);
    // `bundler` is a rails runtime dep but declared ">= 1.15.0", NOT lockstep — excluded.
    expect(lockstepFor('bundler', rails, 'RubyGems').pinned).toBe(false);
    // No prefix matching: these are ordinary rubygems namespaces Rails does not coordinate.
    expect(lockstepFor('activerecord-import', rails, 'RubyGems').pinned).toBe(false);
    expect(lockstepFor('actionpack-action_caching', rails, 'RubyGems').pinned).toBe(false);
  });

  it('never crosses ecosystems in either direction', () => {
    // A gem must not anchor/claim an npm project and vice versa — names are only unique
    // *within* a registry, and there are real npm packages called `rails` and `activesupport`.
    expect(presentFrameworks(['rails', 'puma'], 'npm')).toEqual(new Set());
    expect(presentFrameworks(['rails', 'puma'], 'RubyGems')).toEqual(new Set(['Rails']));
    expect(lockstepFor('activerecord', undefined, 'npm').pinned).toBe(false);
    expect(lockstepFor('next', undefined, 'RubyGems').pinned).toBe(false);
    expect(lockstepFor('react-native', undefined, 'RubyGems').pinned).toBe(false);
  });

  it('requires the anchor: rails components alone are not Rails-coordinated', () => {
    // A project depending on activesupport WITHOUT rails is not a Rails app — the gem
    // versions independently there, exactly like `react` outside Expo (#18).
    expect(presentFrameworks(['activesupport', 'nokogiri'], 'RubyGems')).toEqual(new Set());
    expect(lockstepFor('activesupport', new Set(), 'RubyGems').pinned).toBe(false);
  });
});
