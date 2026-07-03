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

describe('presentFrameworks', () => {
  it('detects frameworks by their marker packages only', () => {
    expect(presentFrameworks(['next', 'react', 'zod']).map((s) => s.framework)).toEqual(['Next.js']);
    expect(presentFrameworks(['expo', 'react']).map((s) => s.framework)).toEqual(['Expo']);
    expect(presentFrameworks(['@sveltejs/kit', 'svelte']).map((s) => s.framework)).toEqual(['SvelteKit']);
    // shared members are NOT markers: react alone proves nothing
    expect(presentFrameworks(['react', 'react-dom', 'lodash'])).toEqual([]);
  });
});

describe('lockstepFor with project context (the dogfood BUG-1 regression)', () => {
  it('attributes react to Next.js in a Next project — never to absent Expo', () => {
    const next = presentFrameworks(['next', 'react', 'react-dom']);
    expect(lockstepFor('react', next)).toMatchObject({ pinned: true, framework: 'Next.js', tool: 'npx @next/codemod upgrade' });
    expect(lockstepFor('react-dom', next)?.framework).toBe('Next.js');
    expect(lockstepFor('eslint-config-next', next)?.framework).toBe('Next.js');
  });

  it('still attributes react to Expo in an Expo project', () => {
    const expo = presentFrameworks(['expo', 'react', 'react-native']);
    expect(lockstepFor('react', expo)).toMatchObject({ pinned: true, framework: 'Expo' });
  });

  it('leaves shared members unpinned when no framework is present', () => {
    expect(lockstepFor('react', []).pinned).toBe(false);
    expect(lockstepFor('eslint-config-next', presentFrameworks(['react', 'vite'])).pinned).toBe(false);
  });
});
