import { describe, expect, it } from 'vitest';

import { lockstepFor } from '../src/lockstep';

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
