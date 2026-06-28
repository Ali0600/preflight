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

  it('leaves independent packages unpinned', () => {
    expect(lockstepFor('fastapi').pinned).toBe(false);
    expect(lockstepFor('lodash').pinned).toBe(false);
    expect(lockstepFor('react-query').pinned).toBe(false); // starts with "react" but not a set member
  });
});
