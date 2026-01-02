// Global mock for better-auth/plugins (ESM module)
export const mockCreateAuthMiddleware = jest.fn((fn) => fn);

jest.mock('better-auth/plugins', () => ({
  createAuthMiddleware: mockCreateAuthMiddleware,
}));
