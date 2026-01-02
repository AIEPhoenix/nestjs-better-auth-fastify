/**
 * Jest E2E Setup
 *
 * This file sets up mocks for ESM modules that Jest cannot import directly.
 *
 * NOTE: These are functional mocks that simulate better-auth behavior.
 * For full integration testing with real better-auth, consider using Vitest.
 */

// Use global to share data across jest module isolation
declare global {
  var __mockAuthUsers: Map<string, any>;
  var __mockAuthSessions: Map<string, any>;
  var __mockAuthApiKeys: Map<string, any>;
}

// Initialize global storage
global.__mockAuthUsers = global.__mockAuthUsers || new Map();
global.__mockAuthSessions = global.__mockAuthSessions || new Map();
global.__mockAuthApiKeys = global.__mockAuthApiKeys || new Map();

// Helper to generate IDs
const generateId = () => Math.random().toString(36).substring(2, 15);

// Mock better-auth/plugins (ESM module)
jest.mock('better-auth/plugins', () => ({
  createAuthMiddleware: jest.fn((fn) => fn),
  admin: jest.fn(() => ({ id: 'admin' })),
  organization: jest.fn(() => ({ id: 'organization' })),
  twoFactor: jest.fn(() => ({ id: 'twoFactor' })),
  bearer: jest.fn(() => ({ id: 'bearer' })),
  apiKey: jest.fn(() => ({ id: 'apiKey' })),
}));

// Mock better-auth with functional implementation using Web APIs
jest.mock('better-auth', () => ({
  betterAuth: jest.fn((config: any) => {
    const basePath = config.basePath || '/api/auth';

    return {
      options: {
        basePath,
        plugins: config.plugins || [],
        hooks: config.hooks || {},
      },
      // Handler receives Web Request, returns Web Response
      handler: async (request: Request): Promise<Response> => {
        const url = new URL(request.url);
        const path = url.pathname.replace(basePath, '');
        const method = request.method;

        // Parse JSON body for POST requests
        let body: any = {};
        if (method === 'POST') {
          try {
            body = await request.json();
          } catch {
            body = {};
          }
        }

        // Get cookies from request
        const cookieHeader = request.headers.get('cookie') || '';
        const sessionToken = cookieHeader.match(
          /better-auth\.session_token=([^;]+)/,
        )?.[1];

        const generateId = () => Math.random().toString(36).substring(2, 15);

        // Sign up
        if (path === '/sign-up/email' && method === 'POST') {
          const userId = generateId();
          const sessionId = generateId();

          const user = {
            id: userId,
            email: body.email,
            name: body.name,
            emailVerified: false,
            image: null,
            role: 'user',
            createdAt: new Date().toISOString(),
          };

          const session = {
            id: sessionId,
            userId,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(
              Date.now() + 7 * 24 * 60 * 60 * 1000,
            ).toISOString(),
          };

          global.__mockAuthUsers.set(userId, user);
          global.__mockAuthSessions.set(sessionId, { session, user });

          return new Response(JSON.stringify({ user, session }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Set-Cookie': `better-auth.session_token=${sessionId}; Path=/; HttpOnly`,
            },
          });
        }

        // Sign in
        if (path === '/sign-in/email' && method === 'POST') {
          const user = Array.from(global.__mockAuthUsers.values()).find(
            (u) => u.email === body.email,
          );

          if (!user) {
            return new Response(
              JSON.stringify({ error: 'Invalid credentials' }),
              {
                status: 401,
                headers: { 'Content-Type': 'application/json' },
              },
            );
          }

          const sessionId = generateId();
          const session = {
            id: sessionId,
            userId: user.id,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(
              Date.now() + 7 * 24 * 60 * 60 * 1000,
            ).toISOString(),
          };

          global.__mockAuthSessions.set(sessionId, { session, user });

          return new Response(JSON.stringify({ user, session }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Set-Cookie': `better-auth.session_token=${sessionId}; Path=/; HttpOnly`,
            },
          });
        }

        // Get session
        if (path === '/session' && method === 'GET') {
          if (!sessionToken || !global.__mockAuthSessions.has(sessionToken)) {
            return new Response(JSON.stringify({ session: null, user: null }), {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            });
          }

          return new Response(
            JSON.stringify(global.__mockAuthSessions.get(sessionToken)),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            },
          );
        }

        // Sign out
        if (path === '/sign-out' && method === 'POST') {
          if (sessionToken) {
            global.__mockAuthSessions.delete(sessionToken);
          }

          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Set-Cookie':
                'better-auth.session_token=; Path=/; HttpOnly; Max-Age=0',
            },
          });
        }

        // Default: not found
        return new Response(JSON.stringify({ error: 'Not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      },
      $context: {
        session: null,
      },
      // API methods used by the auth guard
      api: {
        getSession: async ({ headers }: { headers: Headers }) => {
          const cookieHeader = headers.get('cookie') || '';
          const sessionToken = cookieHeader.match(
            /better-auth\.session_token=([^;]+)/,
          )?.[1];

          // Also check for Bearer token
          const authHeader = headers.get('authorization') || '';
          const bearerToken = authHeader.match(/^Bearer\s+(.+)$/)?.[1];
          const token = sessionToken || bearerToken;

          if (!token || !global.__mockAuthSessions.has(token)) {
            return null;
          }

          return global.__mockAuthSessions.get(token);
        },
        verifyApiKey: async ({ body }: { body: { key: string } }) => {
          // Check if API key exists in mock storage
          if (global.__mockAuthApiKeys.has(body.key)) {
            const keyData = global.__mockAuthApiKeys.get(body.key);
            return {
              valid: true,
              key: keyData,
            };
          }
          return { valid: false, key: null };
        },
      },
    };
  }),
}));

// Mock better-sqlite3 (native module)
jest.mock('better-sqlite3', () => {
  return jest.fn().mockImplementation(() => ({
    pragma: jest.fn(),
    exec: jest.fn(),
    prepare: jest.fn().mockReturnValue({
      run: jest.fn(),
      get: jest.fn(),
      all: jest.fn().mockReturnValue([]),
    }),
    close: jest.fn(),
  }));
});

// Clear mock data before each test file
beforeAll(() => {
  global.__mockAuthUsers.clear();
  global.__mockAuthSessions.clear();
  global.__mockAuthApiKeys.clear();
});

// Extend test timeout for e2e tests
jest.setTimeout(30000);

// Export for tests that need direct access
export const getMockUsers = () => global.__mockAuthUsers;
export const getMockSessions = () => global.__mockAuthSessions;
export const getMockApiKeys = () => global.__mockAuthApiKeys;

/**
 * Helper to set user role directly in mock storage
 * This simulates admin promoting a user
 */
export const setUserRole = (userId: string, role: string) => {
  if (global.__mockAuthUsers.has(userId)) {
    const user = global.__mockAuthUsers.get(userId);
    user.role = role;
    global.__mockAuthUsers.set(userId, user);

    // Also update any active sessions
    for (const [
      sessionId,
      sessionData,
    ] of global.__mockAuthSessions.entries()) {
      if (sessionData.user.id === userId) {
        sessionData.user.role = role;
        global.__mockAuthSessions.set(sessionId, sessionData);
      }
    }
  }
};

/**
 * Helper to set user permissions directly in mock storage
 */
export const setUserPermissions = (userId: string, permissions: string[]) => {
  if (global.__mockAuthUsers.has(userId)) {
    const user = global.__mockAuthUsers.get(userId);
    user.permissions = permissions;
    global.__mockAuthUsers.set(userId, user);

    // Also update any active sessions
    for (const [
      sessionId,
      sessionData,
    ] of global.__mockAuthSessions.entries()) {
      if (sessionData.user.id === userId) {
        sessionData.user.permissions = permissions;
        global.__mockAuthSessions.set(sessionId, sessionData);
      }
    }
  }
};

/**
 * Helper to ban a user directly in mock storage
 */
export const banUser = (userId: string, reason?: string) => {
  if (global.__mockAuthUsers.has(userId)) {
    const user = global.__mockAuthUsers.get(userId);
    user.banned = true;
    user.banReason = reason || 'Banned by test';
    global.__mockAuthUsers.set(userId, user);

    // Also update any active sessions
    for (const [
      sessionId,
      sessionData,
    ] of global.__mockAuthSessions.entries()) {
      if (sessionData.user.id === userId) {
        sessionData.user.banned = true;
        sessionData.user.banReason = reason || 'Banned by test';
        global.__mockAuthSessions.set(sessionId, sessionData);
      }
    }
  }
};

/**
 * Helper to create an API key in mock storage
 */
export const createMockApiKey = (options: {
  key: string;
  userId: string;
  name: string;
  permissions?: Record<string, string[]>;
}) => {
  const keyData = {
    id: `key-${Date.now()}`,
    name: options.name,
    userId: options.userId,
    permissions: options.permissions || {},
    createdAt: new Date().toISOString(),
  };
  global.__mockAuthApiKeys.set(options.key, keyData);
  return keyData;
};
