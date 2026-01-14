/**
 * E2E Test-specific Better Auth Configuration
 *
 * Uses real better-auth with better-sqlite3 in-memory database
 * Each test suite gets an independent auth instance and database
 */
import { betterAuth } from 'better-auth';
import {
  admin,
  organization,
  twoFactor,
  bearer,
  apiKey,
} from 'better-auth/plugins';
import Database from 'better-sqlite3';

// Store database reference for test cleanup
let testDb: ReturnType<typeof Database> | null = null;

/**
 * Create a better-auth instance for testing
 * Each call creates a new in-memory database
 */
export async function createTestAuth() {
  // Close previous database connection
  if (testDb) {
    try {
      testDb.close();
    } catch {
      // Ignore already closed error
    }
  }

  // Create new in-memory database
  testDb = new Database(':memory:');

  const auth = betterAuth({
    basePath: '/api/auth',

    // In-memory database (isolated per test suite)
    database: testDb,

    // Test-specific secret
    secret:
      process.env.BETTER_AUTH_SECRET || 'test-secret-key-for-e2e-testing-only',

    // Email and password authentication
    emailAndPassword: {
      enabled: true,
      requireEmailVerification: false,
    },

    // Trusted origins
    trustedOrigins: ['http://localhost:3000', 'http://127.0.0.1:3000'],

    // Session configuration
    session: {
      expiresIn: 60 * 60 * 24 * 7, // 7 days
      updateAge: 60 * 60 * 24, // 1 day
      freshAge: 60 * 5, // 5 minutes (shorter for testing)
    },

    // User configuration
    user: {
      additionalFields: {
        permissions: {
          type: 'string[]',
          defaultValue: [],
        },
      },
    },

    // Hooks configuration
    hooks: {},

    // Enable all plugins
    plugins: [
      admin({
        defaultRole: 'user',
        adminRole: 'admin',
        impersonationSessionDuration: 60 * 60, // 1 hour
      }),
      organization({
        allowUserToCreateOrganization: true,
        creatorRole: 'owner',
        memberRole: 'member',
        invitationExpiresIn: 60 * 60 * 24 * 7, // 7 days
      }),
      twoFactor({
        issuer: 'NestJS Better Auth E2E Test',
        backupCodeCount: 10,
      }),
      bearer(),
      apiKey(),
    ],
  });

  // Key: Run database migrations to create tables
  await auth.api.getSession({ headers: new Headers() }).catch(() => {
    // Ignore error, this is just to trigger table creation
  });

  // Directly use $migrate method to create tables (if available)
  // @ts-expect-error - Accessing internal API
  if (auth.$Infer) {
    // Use Kysely raw SQL to directly create tables
    runMigrations(testDb);
  } else {
    // Try alternative approach
    runMigrations(testDb);
  }

  return auth;
}

/**
 * Manually run database migrations
 * better-auth table structure
 */
function runMigrations(db: ReturnType<typeof Database>): void {
  // Create user table
  db.exec(`
    CREATE TABLE IF NOT EXISTS "user" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "name" TEXT NOT NULL,
      "email" TEXT NOT NULL UNIQUE,
      "emailVerified" INTEGER NOT NULL DEFAULT 0,
      "image" TEXT,
      "createdAt" TEXT NOT NULL DEFAULT (datetime('now')),
      "updatedAt" TEXT NOT NULL DEFAULT (datetime('now')),
      "role" TEXT DEFAULT 'user',
      "banned" INTEGER DEFAULT 0,
      "banReason" TEXT,
      "banExpires" TEXT,
      "permissions" TEXT DEFAULT '[]',
      "twoFactorEnabled" INTEGER DEFAULT 0
    );
  `);

  // Create session table
  db.exec(`
    CREATE TABLE IF NOT EXISTS "session" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "expiresAt" TEXT NOT NULL,
      "token" TEXT NOT NULL UNIQUE,
      "createdAt" TEXT NOT NULL DEFAULT (datetime('now')),
      "updatedAt" TEXT NOT NULL DEFAULT (datetime('now')),
      "ipAddress" TEXT,
      "userAgent" TEXT,
      "userId" TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
      "impersonatedBy" TEXT,
      "activeOrganizationId" TEXT REFERENCES "organization"("id") ON DELETE SET NULL
    );
  `);

  // Create account table
  db.exec(`
    CREATE TABLE IF NOT EXISTS "account" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "accountId" TEXT NOT NULL,
      "providerId" TEXT NOT NULL,
      "userId" TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
      "accessToken" TEXT,
      "refreshToken" TEXT,
      "idToken" TEXT,
      "accessTokenExpiresAt" TEXT,
      "refreshTokenExpiresAt" TEXT,
      "scope" TEXT,
      "password" TEXT,
      "createdAt" TEXT NOT NULL DEFAULT (datetime('now')),
      "updatedAt" TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Create verification table
  db.exec(`
    CREATE TABLE IF NOT EXISTS "verification" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "identifier" TEXT NOT NULL,
      "value" TEXT NOT NULL,
      "expiresAt" TEXT NOT NULL,
      "createdAt" TEXT DEFAULT (datetime('now')),
      "updatedAt" TEXT DEFAULT (datetime('now'))
    );
  `);

  // Create twoFactor table
  db.exec(`
    CREATE TABLE IF NOT EXISTS "twoFactor" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "secret" TEXT NOT NULL,
      "backupCodes" TEXT NOT NULL,
      "userId" TEXT NOT NULL UNIQUE REFERENCES "user"("id") ON DELETE CASCADE
    );
  `);

  // Create organization table
  db.exec(`
    CREATE TABLE IF NOT EXISTS "organization" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "name" TEXT NOT NULL,
      "slug" TEXT UNIQUE,
      "logo" TEXT,
      "createdAt" TEXT NOT NULL DEFAULT (datetime('now')),
      "metadata" TEXT
    );
  `);

  // Create member table
  db.exec(`
    CREATE TABLE IF NOT EXISTS "member" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "organizationId" TEXT NOT NULL REFERENCES "organization"("id") ON DELETE CASCADE,
      "userId" TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
      "role" TEXT NOT NULL DEFAULT 'member',
      "createdAt" TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Create invitation table
  db.exec(`
    CREATE TABLE IF NOT EXISTS "invitation" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "organizationId" TEXT NOT NULL REFERENCES "organization"("id") ON DELETE CASCADE,
      "email" TEXT NOT NULL,
      "role" TEXT,
      "status" TEXT NOT NULL DEFAULT 'pending',
      "expiresAt" TEXT NOT NULL,
      "inviterId" TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE
    );
  `);

  // Create apikey table
  db.exec(`
    CREATE TABLE IF NOT EXISTS "apikey" (
      "id" TEXT PRIMARY KEY NOT NULL,
      "name" TEXT,
      "start" TEXT,
      "prefix" TEXT,
      "key" TEXT NOT NULL,
      "userId" TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
      "refillInterval" INTEGER,
      "refillAmount" INTEGER,
      "lastRefillAt" TEXT,
      "enabled" INTEGER DEFAULT 1,
      "rateLimitEnabled" INTEGER DEFAULT 0,
      "rateLimitTimeWindow" INTEGER,
      "rateLimitMax" INTEGER,
      "requestCount" INTEGER DEFAULT 0,
      "remaining" INTEGER,
      "lastRequest" TEXT,
      "expiresAt" TEXT,
      "createdAt" TEXT NOT NULL DEFAULT (datetime('now')),
      "updatedAt" TEXT DEFAULT (datetime('now')),
      "permissions" TEXT,
      "metadata" TEXT
    );
  `);

  console.log('✅ Database migrations completed');
}

/**
 * Get the current test database
 */
export function getTestDb() {
  return testDb;
}

/**
 * Close the test database
 */
export function closeTestDb() {
  if (testDb) {
    try {
      testDb.close();
    } catch {
      // Ignore already closed error
    }
    testDb = null;
  }
}

/**
 * Clear all data in the database (but keep table structure)
 */
export function clearTestData() {
  if (!testDb) return;

  try {
    // Delete data from all tables (in foreign key dependency order)
    const tables = [
      'apikey',
      'member',
      'invitation',
      'organization',
      'twoFactor',
      'session',
      'account',
      'user',
    ];

    testDb.exec('PRAGMA foreign_keys = OFF;');
    for (const table of tables) {
      try {
        testDb.exec(`DELETE FROM "${table}";`);
      } catch {
        // Table may not exist
      }
    }
    testDb.exec('PRAGMA foreign_keys = ON;');
  } catch (error) {
    console.warn('Failed to clear test data:', error);
  }
}

export type TestAuth = Awaited<ReturnType<typeof createTestAuth>>;
