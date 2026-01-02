import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';
import path from 'path';

export default defineConfig({
  test: {
    // E2E test directory
    include: ['test/e2e-real/**/*.e2e-spec.ts'],

    // Single file execution (E2E tests need isolation)
    fileParallelism: false,

    // Use node environment
    environment: 'node',

    // Global setup and cleanup
    globalSetup: ['./test/e2e-real/setup/global-setup.ts'],

    // Per-file setup
    setupFiles: ['./test/e2e-real/setup/setup.ts'],

    // Longer timeout (real database operations need more time)
    testTimeout: 30000,
    hookTimeout: 30000,

    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['../src/**/*.ts'],
      exclude: ['../src/**/*.spec.ts', '../src/**/*.d.ts'],
    },
  },
  plugins: [
    // Use SWC for better performance
    swc.vite({
      module: { type: 'es6' },
    }),
    // Support tsconfig paths
    tsconfigPaths(),
  ],
  resolve: {
    alias: {
      '@sapix/nestjs-better-auth-fastify': path.resolve(__dirname, '../src/index.ts'),
    },
  },
});
