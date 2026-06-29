import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // The engine is a workspace package that ships TypeScript source (exports -> ./src),
  // so Next must transpile it rather than expecting a prebuilt dist.
  transpilePackages: ['@preflight/core'],
  // Linting is handled at the repo root (this package is excluded there); don't fail the build on it.
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
