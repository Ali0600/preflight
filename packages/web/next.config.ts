import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { NextConfig } from 'next';

// Monorepo root (two levels up) — so standalone tracing reaches the workspace engine + hoisted deps.
const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

const nextConfig: NextConfig = {
  // The engine is a workspace package that ships TypeScript source (exports -> ./src),
  // so Next must transpile it rather than expecting a prebuilt dist.
  transpilePackages: ['@preflight/core'],
  // Linting is handled at the repo root (this package is excluded there); don't fail the build on it.
  eslint: { ignoreDuringBuilds: true },
  // Self-contained server output (traces every dep into .next/standalone) — the Dockerfile runs it.
  output: 'standalone',
  outputFileTracingRoot: repoRoot,
};

export default nextConfig;
