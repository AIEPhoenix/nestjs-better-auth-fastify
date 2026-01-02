/**
 * Vitest E2E Per-file Setup
 *
 * This file runs before each test file
 */
import { beforeAll, afterAll } from 'vitest';

// Ensure environment variables are set correctly
beforeAll(() => {
  process.env.NODE_ENV = 'test';
});

afterAll(() => {
  // Clean up any remaining resources
});
