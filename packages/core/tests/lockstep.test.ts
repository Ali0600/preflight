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
