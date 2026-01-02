/**
 * Vitest E2E Global Setup
 *
 * This file runs once before all tests start,
 * used for global database initialization and environment preparation
 */

export async function setup() {
  // Set environment variables
  process.env.NODE_ENV = 'test';
  process.env.BETTER_AUTH_SECRET =
    'test-secret-key-for-e2e-testing-only-do-not-use-in-production';

  console.log('\n🚀 Starting E2E tests with REAL better-auth...\n');
}

export async function teardown() {
  console.log('\n✅ E2E tests completed\n');
}
